# Harmless imitation of "read secrets while connected to the internet".
# Connects to 203.0.113.7:443 (TEST-NET-3, unroutable) and holds ~/.ssh open as a directory
# (no key is read). Expected: CRITICAL "Python читає SSH-ключі і має з'єднання з інтернетом",
# process frozen. Kill it afterwards: kill -9 <pid>.
import os, socket, time

s = socket.socket()
s.setblocking(False)
try:
    s.connect(("203.0.113.7", 443))
except BlockingIOError:
    pass
time.sleep(2)
ssh = os.path.expanduser("~/.ssh")
if not os.path.isdir(ssh):
    raise SystemExit("~/.ssh does not exist on this Mac, nothing to test")
fd = os.open(ssh, os.O_RDONLY)
time.sleep(30)
