#!/usr/bin/env python3
"""
dashboard.py - a Streamlit dashboard for the SSH detection lab.

Run it (from the folder that holds loggen.py and detect.py):
    pip install streamlit
    streamlit run dashboard.py

How it fits together. Every time you touch a control, Streamlit reruns this
whole file from the top:

    1. get a log  -> loggen.generate()  (or a log file you upload)
    2. parse it   -> detect.parse_lines()
    3. detect     -> detect.detect()  with the threshold and window sliders
    4. draw       -> numbers, charts, alerts table, answer key

Generating a log only happens when you click the button. The log is kept in
st.session_state, which survives the reruns, so moving a slider re-runs
detection on the SAME log.
"""

import json

import altair as alt
import pandas as pd
import streamlit as st

import detect
import loggen

st.set_page_config(page_title="SSH Detection Lab", page_icon="🛡️", layout="wide")

FLAGGED = "Flagged"
NOT_FLAGGED = "Not flagged"
SEVERITY_LABEL = {"critical": "🔴 Critical", "high": "🟠 High"}


def chart_colors():
    """Blue for 'not flagged', orange for 'flagged'. The two colours were
    checked for colour-blind safety, with separate shades for light and dark."""
    theme = getattr(st.context, "theme", None)
    dark = getattr(theme, "type", None) == "dark"
    return ["#d95926", "#3987e5"] if dark else ["#eb6834", "#2a78d6"]


def status_color():
    return alt.Color("status:N", title=None,
                     scale=alt.Scale(domain=[FLAGGED, NOT_FLAGGED], range=chart_colors()),
                     legend=alt.Legend(orient="top"))


def bucket_minutes(span_hours):
    """Pick a bar width that gives roughly 100 bars or fewer on the timeline."""
    for minutes in (5, 10, 15, 30, 60, 120, 240):
        if span_hours * 60 / minutes <= 120:
            return minutes
    return 1440


# ---------------------------------------------------------------------------
# Step 1: get a log (sidebar)
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("1. Get a log")
    source = st.radio("Source", ["Generate", "Upload a file"], horizontal=True)

    if source == "Generate":
        difficulty = st.selectbox("Difficulty", list(loggen.LEVELS))
        hours = st.slider("Hours of history", 6, 72, 24, step=6)
        fixed = st.checkbox("Fixed seed (same log every time)")
        seed = st.number_input("Seed", 0, 1_000_000, 42, disabled=not fixed)
        clicked = st.button("Generate new log", type="primary", width="stretch")

        # Make a new log when the button is clicked, or when the settings
        # changed since the last one (e.g. you picked another difficulty)
        settings = (difficulty, hours, int(seed) if fixed else None)
        current = st.session_state.get("log")
        if clicked or current is None or current.get("settings") != settings:
            try:
                lines, answer_key = loggen.generate(difficulty, hours=hours, seed=settings[2])
                st.session_state.log = {"lines": lines, "key": answer_key,
                                        "settings": settings,
                                        "label": f"Generated log, {difficulty}, {hours}h"}
            except ValueError as err:
                st.error(str(err))
    else:
        upload = st.file_uploader("An auth.log file")
        if upload is not None:
            text = upload.getvalue().decode("utf-8", errors="replace")
            st.session_state.log = {"lines": text.splitlines(), "key": None,
                                    "label": f"Uploaded file: {upload.name}"}
        elif st.session_state.get("log", {}).get("key") is not None:
            st.session_state.pop("log")   # don't keep showing the generated log

    st.header("2. Tune the rule")
    threshold = st.slider("Failed logins needed", 1, 50, 10,
                          help="How many failures from one IP raise an alert")
    window = st.slider("Within this many seconds", 10, 900, 60, step=10,
                       help="How close together those failures must be")

st.title("🛡️ SSH Detection Lab")

log = st.session_state.get("log")
if log is None:
    st.info("Upload a log file in the sidebar, or switch to **Generate**.")
    st.stop()

lines, answer_key = log["lines"], log["key"]
st.caption(f"{log['label']} · Rule: **{threshold}+** failed logins from one IP "
           f"within **{window} s**")

# ---------------------------------------------------------------------------
# Steps 2 and 3: parse and detect (reruns on every slider move)
# ---------------------------------------------------------------------------

failures, accepted, skipped = detect.parse_lines(lines)
alerts = detect.detect(failures, accepted, threshold, window)

flagged_ips = {a["source_ip"] for a in alerts if a["rule"] == "ssh_bruteforce"}
brute_alerts = sum(a["rule"] == "ssh_bruteforce" for a in alerts)
breakins = sum(a["rule"] == "ssh_compromise" for a in alerts)

# ---------------------------------------------------------------------------
# Step 4: draw
# ---------------------------------------------------------------------------

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Log lines", f"{len(lines):,}")
c2.metric("Failed logins", f"{sum(len(t) for t in failures.values()):,}")
c3.metric("IPs with failures", len(failures))
c4.metric("Brute-force alerts", brute_alerts)
c5.metric("Break-in alerts", breakins)
if skipped:
    st.warning(f"{skipped} lines didn't look like SSH log lines and were skipped.")

rows = [(t, ip) for ip, times in failures.items() for t in times]
if not rows:
    st.info("No failed logins in this log, so there's nothing to chart.")
else:
    df = pd.DataFrame(rows, columns=["time", "ip"])
    df["status"] = [FLAGGED if ip in flagged_ips else NOT_FLAGGED for ip in df["ip"]]

    left, right = st.columns([2, 1])

    with left:
        span = (df["time"].max() - df["time"].min()).total_seconds() / 3600
        minutes = bucket_minutes(span)
        df["bucket"] = df["time"].dt.floor(f"{minutes}min")
        timeline = df.groupby(["bucket", "status"]).size().reset_index(name="failed")

        st.subheader("Failed logins over time")
        st.altair_chart(
            alt.Chart(timeline).mark_bar().encode(
                x=alt.X("bucket:T", title=None),
                y=alt.Y("failed:Q", title=f"Failed logins per {minutes} min"),
                color=status_color(),
                order=alt.Order("status:N", sort="descending"),
                tooltip=[alt.Tooltip("bucket:T", title="From", format="%b %d %H:%M"),
                         alt.Tooltip("status:N", title="Status"),
                         alt.Tooltip("failed:Q", title="Failed logins")],
            ).properties(height=330),
            width="stretch")

    with right:
        top = df.groupby("ip").size().reset_index(name="failed").nlargest(15, "failed")
        top["status"] = [FLAGGED if ip in flagged_ips else NOT_FLAGGED for ip in top["ip"]]

        st.subheader("Top 15 IPs")
        st.altair_chart(
            alt.Chart(top).mark_bar(cornerRadiusEnd=4).encode(
                y=alt.Y("ip:N", sort="-x", title=None,
                        axis=alt.Axis(labelOverlap=False)),   # show every IP
                x=alt.X("failed:Q", title="Failed logins (whole log)"),
                color=status_color(),
                tooltip=[alt.Tooltip("ip:N", title="IP"),
                         alt.Tooltip("failed:Q", title="Failed logins"),
                         alt.Tooltip("status:N", title="Status")],
            ).properties(height=alt.Step(22)),   # 22 px per IP row
            width="stretch")

    st.caption("Blue spikes on the timeline, or long blue bars in the top IPs, are "
               "activity your rule did not flag. That's where hidden attacks live.")

st.subheader(f"Alerts ({len(alerts)})")
if alerts:
    table = pd.DataFrame([{
        "Severity": SEVERITY_LABEL.get(a["severity"], a["severity"]),
        "First seen": a["first_seen"].replace("T", " "),
        "Alert": a["title"],
        "Failed logins": a.get("failed_attempts"),
        "Rule": a["rule"],
    } for a in alerts])
    table["Failed logins"] = table["Failed logins"].astype("Int64")
    st.dataframe(table, hide_index=True, width="stretch")
else:
    st.write("No alerts with the current rule.")

d1, d2, _ = st.columns([1, 1, 3])
d1.download_button("Download alerts.json", json.dumps(alerts, indent=2),
                   file_name="alerts.json", mime="application/json", width="stretch")
d2.download_button("Download auth.log", "\n".join(lines) + "\n",
                   file_name="auth.log", mime="text/plain", width="stretch")

# ---------------------------------------------------------------------------
# Answer key and score (generated logs only)
# ---------------------------------------------------------------------------

if answer_key:
    attacker_ips = set()
    for attack in answer_key:
        attacker_ips.update(attack["ips"])
        if attack.get("login_ip"):
            attacker_ips.add(attack["login_ip"])
    compromise_ips = {a["source_ip"] for a in alerts if a["rule"] == "ssh_compromise"}
    false_alarms = sum(a["source_ip"] not in attacker_ips for a in alerts)

    rows, caught = [], 0
    for attack in answer_key:
        hit = bool(flagged_ips & set(attack["ips"]))
        caught += hit
        breakin = "No"
        if attack["victim"]:
            login_ip = attack.get("login_ip") or attack["ips"][0]
            seen = login_ip in compromise_ips
            breakin = f"As '{attack['victim']}': " + ("✅ caught" if seen else "❌ missed")
        rows.append({
            "Attack": attack["type"],
            "IPs": attack["ips"][0] if len(attack["ips"]) == 1 else f"{len(attack['ips'])} IPs",
            "Attempts": attack["attempts"],
            "Start": f"{attack['start']:%b %d %H:%M}",
            "Detected": "✅ Caught" if hit else "❌ Missed",
            "Break-in": breakin,
        })

    with st.expander("Reveal the answer key (try tuning your rule first!)"):
        st.markdown(f"**Score:** caught **{caught} of {len(answer_key)}** attacks · "
                    f"**{false_alarms}** false-alarm alert(s)")
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        st.markdown("**Why each one is tricky**")
        st.markdown("\n".join(f"- **{a['type']}:** {a['why']}" for a in answer_key))

with st.expander("Peek at the raw log (first 200 lines)"):
    st.code("\n".join(lines[:200]), language=None)
