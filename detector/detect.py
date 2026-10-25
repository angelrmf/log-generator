#!/usr/bin/env python3
"""
detect.py - a tiny detection engine for SSH logs.

Reads an auth.log-style file (like the ones loggen.py makes) and raises alerts
using two rules:

  Rule 1  ssh_bruteforce   THRESHOLD or more failed logins from one IP
                           within WINDOW seconds
  Rule 2  ssh_compromise   a successful login from an IP that Rule 1
                           has already flagged

Alerts are printed and also saved to alerts.json. That file is the kind of
data a case tool like TheHive would receive from a SIEM.

Examples:
    python3 detect.py
    python3 detect.py auth.log --threshold 5 --window 30
"""

import argparse
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Step 1: parsing - turn text lines into structured data
# ---------------------------------------------------------------------------

# Splits a syslog line into its parts: date, time, host, process id, message.
# Newer OpenSSH versions (9.8+) log as "sshd-session" instead of "sshd".
LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:-session)?\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

# The system logger squashes identical lines into one summary like
# "message repeated 3 times: [ Failed password for root from ... ]"
REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<inner>.*?)\s*\]$")

# Matches both "Failed password for bob from ..." and
# "Failed password for invalid user admin from ..."
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
)

# \S+ rather than \w+, so methods like "keyboard-interactive/pam" match too
ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port"
)


def parse_time(month, day, clock, now):
    """Syslog timestamps have no year, so we assume the current one."""
    ts = datetime.strptime(f"{now.year} {month} {day} {clock}", "%Y %b %d %H:%M:%S")
    if ts > now + timedelta(days=1):   # e.g. reading December logs in January
        ts = ts.replace(year=now.year - 1)
    return ts


def parse_lines(lines):
    """Turn log lines into the data the rules need.

    `lines` can be anything you can loop over that gives strings: an open
    file, or a list of lines already in memory (that's what the dashboard
    passes in).

    Returns:
        failures: dict mapping ip -> list of timestamps of failed logins
        accepted: list of (timestamp, user, ip) for successful logins
        skipped:  how many lines didn't look like sshd syslog at all
    """
    now = datetime.now()
    failures = defaultdict(list)
    accepted = []
    skipped = 0

    for line in lines:
        m = LINE_RE.match(line)
        if not m:
            skipped += 1
            continue

        ts = parse_time(m["month"], m["day"], m["clock"], now)
        message = m["message"]

        # Unpack "message repeated N times: [ ... ]" so each copy counts
        repeats = 1
        rep = REPEAT_RE.match(message)
        if rep:
            repeats, message = int(rep["n"]), rep["inner"]

        failed = FAILED_RE.search(message)
        if failed:
            failures[failed["ip"]].extend([ts] * repeats)
            continue

        ok = ACCEPTED_RE.search(message)
        if ok:
            accepted.append((ts, ok["user"], ok["ip"]))

    return failures, accepted, skipped


def read_events(path):
    """Same as parse_lines, but reads straight from a log file."""
    with open(path) as f:
        return parse_lines(f)


# ---------------------------------------------------------------------------
# Step 2: detection - the rules
# ---------------------------------------------------------------------------

def split_into_runs(times, gap):
    """Split one IP's failed logins (oldest to newest) into separate runs.

    A pause longer than `gap` seconds starts a new run, so an attacker who
    comes back hours later counts as two incidents instead of one.
    """
    runs = [[times[0]]]
    for t in times[1:]:
        if (t - runs[-1][-1]).total_seconds() > gap:
            runs.append([t])
        else:
            runs[-1].append(t)
    return runs


def busiest_window(times, window):
    """Slide a time window along the failures and return the most that ever
    fit inside `window` seconds at once."""
    best = 0
    in_window = deque()
    for t in times:
        in_window.append(t)

        # Forget failures that are too old to count towards this window
        while (t - in_window[0]).total_seconds() > window:
            in_window.popleft()

        best = max(best, len(in_window))
    return best


def detect(failures, accepted, threshold, window):
    """Apply both rules and return a list of alert dictionaries."""
    alerts = []
    flagged = defaultdict(list)   # ip -> start times of its brute-force runs

    # Rule 1: brute force
    for ip, times in failures.items():
        for run in split_into_runs(times, gap=window):
            if busiest_window(run, window) < threshold:
                continue   # not enough failures close together: probably just noise

            flagged[ip].append(run[0])
            alerts.append({
                "rule": "ssh_bruteforce",
                "title": f"SSH brute force from {ip}",
                "severity": "high",
                "source_ip": ip,
                "failed_attempts": len(run),
                "first_seen": run[0].isoformat(),
                "last_seen": run[-1].isoformat(),
                "tags": ["ssh", "brute-force"],
            })

    # Rule 2: a successful login from an IP after it started brute-forcing
    for ts, user, ip in accepted:
        if any(start <= ts for start in flagged.get(ip, [])):
            alerts.append({
                "rule": "ssh_compromise",
                "title": f"Successful login as '{user}' from brute-forcing IP {ip}",
                "severity": "critical",
                "source_ip": ip,
                "user": user,
                "first_seen": ts.isoformat(),
                "last_seen": ts.isoformat(),
                "tags": ["ssh", "compromise"],
            })

    alerts.sort(key=lambda a: a["first_seen"])   # ISO timestamps sort correctly as text
    return alerts


# ---------------------------------------------------------------------------
# Step 3: output
# ---------------------------------------------------------------------------

def print_alerts(alerts):
    if not alerts:
        print("No alerts.")
        return
    for a in alerts:
        when = a["first_seen"].replace("T", " ")
        print(f"[{a['severity'].upper():<8}] {when}  {a['title']}")
        if a["rule"] == "ssh_bruteforce":
            last = a["last_seen"].replace("T", " ")
            print(f"             {a['failed_attempts']} failed logins, last one at {last}")


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute force in a log file.")
    parser.add_argument("logfile", nargs="?", default="auth.log",
                        help="log file to scan (default: auth.log)")
    parser.add_argument("--threshold", type=int, default=10,
                        help="failed logins needed to raise an alert (default: 10)")
    parser.add_argument("--window", type=int, default=60,
                        help="time window in seconds (default: 60)")
    parser.add_argument("-o", "--output", default="alerts.json",
                        help="where to save the alerts as JSON (default: alerts.json)")
    args = parser.parse_args()

    try:
        failures, accepted, skipped = read_events(args.logfile)
    except FileNotFoundError:
        print(f"Can't find '{args.logfile}'. Make one first with: python3 loggen.py")
        return

    total_failed = sum(len(t) for t in failures.values())
    print(f"Read {args.logfile}: {total_failed} failed logins from {len(failures)} IPs, "
          f"{len(accepted)} successful logins, {skipped} unparseable lines.")
    print(f"Rule: {args.threshold}+ failures from one IP within {args.window}s\n")

    alerts = detect(failures, accepted, args.threshold, args.window)
    print_alerts(alerts)

    with open(args.output, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\n{len(alerts)} alert(s) saved to {args.output}")


if __name__ == "__main__":
    main()
