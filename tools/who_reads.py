# Finds out what keeps reading a watched path (e.g. a false "someone read ~/.ssh" alert).
# Polls the path's atime 20x per second while BotAlert keeps it armed; on every read it prints the
# processes started in the last few seconds and whoever holds the path open.
#
#   python3 tools/who_reads.py ~/.ssh [minutes=20] [max_events=3]
import os, subprocess, sys, time

path = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/.ssh")
deadline = time.time() + 60 * float(sys.argv[2] if len(sys.argv) > 2 else 20)
max_events = int(sys.argv[3] if len(sys.argv) > 3 else 3)
me = os.getpid()


def young_processes(max_age=8):
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,etime=,user=,args="], capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5 or int(parts[0]) == me:
            continue
        et = parts[2]
        if "-" in et or et.count(":") > 1:
            continue
        m, s = et.split(":")
        if int(m) * 60 + int(s) <= max_age:
            rows.append(line.strip()[:300])
    return rows


last = os.stat(path).st_atime_ns
events = 0
print(f"watching {path}", flush=True)
while time.time() < deadline and events < max_events:
    time.sleep(0.05)
    try:
        a = os.stat(path).st_atime_ns
    except FileNotFoundError:
        continue
    if a > last:
        events += 1
        print(f"\n=== read #{events} at {time.strftime('%H:%M:%S')} ===", flush=True)
        print("-- started in the last 8 s:")
        print("\n".join(young_processes()) or "(none)")
        holders = subprocess.run(["lsof", "-nP", "--", path], capture_output=True, text=True).stdout.strip()
        print("-- holding it open:\n" + (holders or "(none)"), flush=True)
    last = a
print("\ndone", flush=True)
