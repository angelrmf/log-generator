#!/usr/bin/env python3
"""
loggen.py - generate fake SSH log lines (Linux auth.log style) for practising
log parsing, detection rules and dashboards.

Every log mixes normal users logging in, internet scanners trying one guess
and leaving, and a few hidden attacks. The first attack ends with the attacker
getting in, so you can practise spotting a compromise, not just an attack.

Difficulty levels (--difficulty):
  easy          Loud, fast brute-force bursts. A simple rule like
                "10 failures from one IP in 60 seconds" catches everything.
  intermediate  More noise, plus attacks built to dodge that simple rule:
                a slow brute force, password spraying, and an attacker who
                comes back hours later for a second round.
  hard          Lots of noise, a remote worker who legitimately logs in from
                outside, a "low and slow" attack spread over hours, and a
                botnet where no single IP tries more than a few times. The
                break-in comes from an IP that never failed a single login.

Every external IP comes from ranges reserved for documentation (RFC 5737),
so none of them belong to real machines.

Examples:
    python3 loggen.py
    python3 loggen.py --difficulty hard
    python3 loggen.py --difficulty intermediate --seed 42 --output test.log
"""

import argparse
import random
import sys
from datetime import datetime, timedelta

HOSTNAME = "webserver01"

# Real users, their user IDs, and the internal IPs they normally log in from
USERS = {
    "alice":  {"uid": 1001, "ips": ["192.168.1.23", "192.168.1.24"]},
    "bob":    {"uid": 1002, "ips": ["192.168.1.40"]},
    "carol":  {"uid": 1003, "ips": ["192.168.1.57", "10.0.0.12"]},
    "deploy": {"uid": 1004, "ips": ["10.0.0.5"]},
}

# Usernames that attackers like to guess
GUESSED_USERS = ["root", "admin", "test", "oracle", "ubuntu",
                 "postgres", "user", "guest", "git", "pi"]

# Reserved documentation ranges: they never point at real computers
ATTACKER_NETS = ["203.0.113", "198.51.100", "192.0.2"]
IP_POOL_SIZE = len(ATTACKER_NETS) * 254

# Hard mode only: alice sometimes works from home, so a successful login
# from outside is NOT automatically an attack
REMOTE_WORKER = ("alice", "203.0.113.50")

# What each difficulty level contains. The first attack in each list is the
# one that succeeds (unless you pass --no-compromise).
LEVELS = {
    "easy": {
        "logins": 30, "noise": 40, "typo_rate": 0.10, "remote_worker": False,
        "attacks": ["fast", "fast", "fast"],
    },
    "intermediate": {
        "logins": 50, "noise": 120, "typo_rate": 0.20, "remote_worker": False,
        "attacks": ["slow", "fast", "spray", "comeback"],
    },
    "hard": {
        "logins": 60, "noise": 250, "typo_rate": 0.25, "remote_worker": True,
        "attacks": ["botnet", "low_and_slow", "spray", "fast"],
    },
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

used_ips = set()   # every external IP handed out so far in this run


def fresh_attacker_ip():
    """Pick an external IP nobody else has used yet.

    Without this, a random scanner could end up with the same IP as an
    attacker, which quietly makes the answer key wrong.
    """
    if len(used_ips) >= IP_POOL_SIZE:
        sys.exit("Ran out of fake IP addresses. Try a lower --noise.")
    while True:
        ip = f"{random.choice(ATTACKER_NETS)}.{random.randint(1, 254)}"
        if ip not in used_ips:
            used_ips.add(ip)
            return ip


def new_pid():
    return random.randint(1000, 65000)


def new_port():
    return random.randint(32768, 60999)


def format_line(ts, pid, message):
    """Build one syslog-style line: 'Oct 23 21:17:03 host sshd[123]: message'."""
    stamp = f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"  # syslog pads the day with a space
    return f"{stamp} {HOSTNAME} sshd[{pid}]: {message}"


# ---------------------------------------------------------------------------
# Building blocks. Events are (timestamp, pid, message) tuples; they are
# only turned into text lines at the very end.
# ---------------------------------------------------------------------------

def failed_guess(ts, ip, user):
    """One failed password attempt.

    Like real sshd, a username that doesn't exist on the server gets an
    extra 'Invalid user' line first.
    """
    pid, port = new_pid(), new_port()
    if user in USERS or user == "root":
        return [(ts, pid, f"Failed password for {user} from {ip} port {port} ssh2")]
    return [
        (ts, pid, f"Invalid user {user} from {ip} port {port}"),
        (ts, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2"),
    ]


def successful_login(ts, ip, user, method="password", pid=None):
    pid = pid or new_pid()
    uid = USERS[user]["uid"]
    return [
        (ts, pid, f"Accepted {method} for {user} from {ip} port {new_port()} ssh2"),
        (ts, pid, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)"),
    ]


def normal_session(ts, typo_rate, remote_worker):
    """A legitimate user logs in, works for a while, logs out."""
    user = random.choice(list(USERS))
    ip = random.choice(USERS[user]["ips"])
    if remote_worker and user == REMOTE_WORKER[0] and random.random() < 0.5:
        ip = REMOTE_WORKER[1]

    events = []
    if random.random() < typo_rate:   # mistyped password before getting it right
        events += failed_guess(ts, ip, user)
        ts += timedelta(seconds=random.randint(3, 10))

    pid = new_pid()
    events += successful_login(ts, ip, user, random.choice(["password", "publickey"]), pid)
    end = ts + timedelta(minutes=random.randint(1, 90))
    events.append((end, pid, f"pam_unix(sshd:session): session closed for user {user}"))
    return events


def scanner_probe(ts):
    """Internet background noise: one guess from a random IP, then gone."""
    return failed_guess(ts, fresh_attacker_ip(), random.choice(GUESSED_USERS))


def guess_series(t0, ip, attempts, min_gap, max_gap, victim=None):
    """`attempts` guesses from one IP, min_gap..max_gap seconds apart.

    If `victim` is set, the last 3 guesses target that real account and the
    attacker then gets in. Returns (events, time of the last event).
    """
    events = []
    ts = t0
    for i in range(attempts):
        if i > 0:
            ts += timedelta(seconds=random.randint(min_gap, max_gap))
        user = victim if (victim and i >= attempts - 3) else random.choice(GUESSED_USERS)
        events += failed_guess(ts, ip, user)
    if victim:
        ts += timedelta(seconds=random.randint(2, max(2, max_gap)))
        events += successful_login(ts, ip, victim)
    return events, ts


def pick_victim(compromise):
    return random.choice(list(USERS)) if compromise else None


# ---------------------------------------------------------------------------
# Attack types. Each takes a start time and returns (events, info), where
# info is that attack's entry in the answer key.
# ---------------------------------------------------------------------------

def attack_fast(t0, compromise):
    ip, victim = fresh_attacker_ip(), pick_victim(compromise)
    attempts = random.randint(20, 80)
    events, _ = guess_series(t0, ip, attempts, 0, 3, victim)
    return events, {"type": "fast brute force", "ips": [ip], "attempts": attempts,
                    "victim": victim,
                    "why": "Loud and fast. The basic threshold rule should catch it."}


def attack_slow(t0, compromise):
    ip, victim = fresh_attacker_ip(), pick_victim(compromise)
    attempts = random.randint(15, 40)
    events, _ = guess_series(t0, ip, attempts, 10, 40, victim)
    return events, {"type": "slow brute force", "ips": [ip], "attempts": attempts,
                    "victim": victim,
                    "why": "One guess every 10-40 seconds, so it never reaches "
                           "10 in a minute. Try a longer window."}


def attack_comeback(t0, compromise):
    """Same IP, two separate fast bursts a few hours apart."""
    ip, victim = fresh_attacker_ip(), pick_victim(compromise)
    first = random.randint(15, 40)
    second = random.randint(15, 40)
    events, end = guess_series(t0, ip, first, 0, 3)
    t1 = end + timedelta(hours=random.randint(1, 4), minutes=random.randint(0, 59))
    more, _ = guess_series(t1, ip, second, 0, 3, victim)
    return events + more, {
        "type": "comeback (two bursts)", "ips": [ip], "attempts": first + second,
        "victim": victim,
        "why": f"The same IP attacks twice ({first} then {second} attempts). "
               "A good detector reports two separate incidents."}


def attack_spray(t0, compromise):
    """One IP tries many different usernames, only a guess or two each."""
    ip, victim = fresh_attacker_ip(), pick_victim(compromise)
    targets = list(USERS) + random.sample(GUESSED_USERS, 4)
    events, ts, attempts = [], t0, 0
    for _ in range(random.randint(1, 2)):
        random.shuffle(targets)
        for user in targets:
            if attempts:
                ts += timedelta(seconds=random.randint(20, 90))
            events += failed_guess(ts, ip, user)
            attempts += 1
    if victim:
        ts += timedelta(seconds=random.randint(20, 90))
        events += successful_login(ts, ip, victim)
    return events, {"type": "password spray", "ips": [ip], "attempts": attempts,
                    "victim": victim,
                    "why": "Few guesses per username, spread out. Count how many "
                           "DIFFERENT usernames one IP tries, and notice it "
                           "targets real accounts."}


def attack_low_and_slow(t0, compromise):
    ip, victim = fresh_attacker_ip(), pick_victim(compromise)
    attempts = random.randint(20, 40)
    events, _ = guess_series(t0, ip, attempts, 120, 480, victim)
    return events, {"type": "low and slow", "ips": [ip], "attempts": attempts,
                    "victim": victim,
                    "why": "One guess every 2-8 minutes for hours. No time window "
                           "catches it; look at each IP's total over the whole day."}


def attack_botnet(t0, compromise):
    """Many IPs, each trying only 2-4 times, all within ~15 minutes."""
    bots = [fresh_attacker_ip() for _ in range(random.randint(15, 30))]
    targets = list(USERS) + ["root", "admin"]
    events, attempts = [], 0
    last = t0
    for ip in bots:
        ts = t0 + timedelta(seconds=random.randint(0, 900))
        for _ in range(random.randint(2, 4)):
            events += failed_guess(ts, ip, random.choice(targets))
            attempts += 1
            last = max(last, ts)
            ts += timedelta(seconds=random.randint(5, 60))

    info = {"type": "botnet", "ips": bots, "attempts": attempts, "victim": None,
            "why": "No single IP crosses any threshold. Count failures across ALL "
                   "IPs per time window, or per targeted username."}
    if compromise:
        victim, login_ip = pick_victim(True), fresh_attacker_ip()
        login_time = last + timedelta(minutes=random.randint(10, 60))
        events += successful_login(login_time, login_ip, victim)
        info.update(victim=victim, login_ip=login_ip)
        info["why"] += (f" The break-in comes from {login_ip}, which never failed "
                        "a login. Connect it to the botnet by the username.")
    return events, info


ATTACKS = {
    "fast": attack_fast,
    "slow": attack_slow,
    "comeback": attack_comeback,
    "spray": attack_spray,
    "low_and_slow": attack_low_and_slow,
    "botnet": attack_botnet,
}


def place_attack(builder, compromise, start, end):
    """Build an attack, then slide it to a random spot that fits entirely
    inside the log's time range."""
    base = datetime(2000, 1, 1)
    events, info = builder(base, compromise)
    duration = max(e[0] for e in events) - base
    room = int(((end - start) - duration).total_seconds()) - 60
    if room < 0:
        sys.exit(f"--hours is too short for a '{info['type']}' attack, which lasts "
                 f"about {duration.total_seconds() / 3600:.1f} hours. "
                 "Try a bigger --hours.")
    shift = (start - base) + timedelta(seconds=random.randint(0, room))
    events = [(ts + shift, pid, msg) for ts, pid, msg in events]
    info["start"] = min(e[0] for e in events)
    info["end"] = max(e[0] for e in events)
    return events, info


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def print_answer_key(attacks):
    print("Answer key (don't peek while you're writing your detector!):")
    for a in sorted(attacks, key=lambda a: a["start"]):
        if len(a["ips"]) == 1:
            who = a["ips"][0]
        else:
            who = f"{len(a['ips'])} IPs, e.g. {', '.join(a['ips'][:3])}"
        print(f"\n  [{a['type']}] {who}")
        print(f"    {a['attempts']} failed attempts, "
              f"{a['start']:%b %d %H:%M:%S} to {a['end']:%b %d %H:%M:%S}")
        if a["victim"]:
            via = f" from {a['login_ip']}" if a.get("login_ip") else ""
            print(f"    SUCCEEDED: logged in as '{a['victim']}'{via}")
        print(f"    Why it's tricky: {a['why']}")


def main():
    parser = argparse.ArgumentParser(description="Generate fake SSH auth.log lines.")
    parser.add_argument("-d", "--difficulty", choices=LEVELS, default="easy",
                        help="easy, intermediate or hard (default: easy)")
    parser.add_argument("-o", "--output", default="auth.log",
                        help="file to write (default: auth.log)")
    parser.add_argument("--hours", type=int, default=24,
                        help="how many hours of history to simulate (default: 24)")
    parser.add_argument("--logins", type=int,
                        help="number of normal user sessions (default: set by difficulty)")
    parser.add_argument("--noise", type=int,
                        help="number of one-off scanner probes (default: set by difficulty)")
    parser.add_argument("--attacks", "--brute-force", dest="attacks", type=int,
                        help="number of attacks (default: set by difficulty)")
    parser.add_argument("--no-compromise", action="store_true",
                        help="make every attack fail (default: the first one succeeds)")
    parser.add_argument("--seed", type=int, default=None,
                        help="random seed, for repeatable output")
    args = parser.parse_args()

    if args.hours < 1:
        sys.exit("--hours must be at least 1.")
    if args.seed is not None:
        random.seed(args.seed)

    level = LEVELS[args.difficulty]
    logins = level["logins"] if args.logins is None else args.logins
    noise = level["noise"] if args.noise is None else args.noise
    count = len(level["attacks"]) if args.attacks is None else args.attacks

    if level["remote_worker"]:
        used_ips.add(REMOTE_WORKER[1])   # keep scanners off the remote worker's IP

    end = datetime.now().replace(microsecond=0)
    start = end - timedelta(hours=args.hours)

    def random_time():
        return start + timedelta(seconds=random.randint(0, args.hours * 3600))

    events = []
    for _ in range(logins):
        events += normal_session(random_time(), level["typo_rate"], level["remote_worker"])
    for _ in range(noise):
        events += scanner_probe(random_time())

    attacks = []
    for i in range(count):
        kind = level["attacks"][i % len(level["attacks"])]   # cycle if --attacks is bigger
        compromise = (i == 0 and not args.no_compromise)
        burst, info = place_attack(ATTACKS[kind], compromise, start, end)
        events += burst
        attacks.append(info)

    # Sessions still open "now" lose their closing line, just like a real
    # live log. Then sort by time (stable, so same-second lines keep order).
    events = [e for e in events if e[0] <= end]
    events.sort(key=lambda e: e[0])

    with open(args.output, "w") as f:
        for ts, pid, message in events:
            f.write(format_line(ts, pid, message) + "\n")

    print(f"Wrote {len(events)} lines to {args.output} (difficulty: {args.difficulty})\n")
    print_answer_key(attacks)


if __name__ == "__main__":
    main()
