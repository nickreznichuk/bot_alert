// Harmless imitation of a BeaverTail-style stealer, used to check that BotAlert reacts.
// It never reads file contents and never sends data: it connects to 203.0.113.1 (TEST-NET-3,
// unroutable, stays in SYN_SENT) on backdoor port 1224, then only *lists* ~/.ssh and Chrome's
// extension-settings folder. Expected: "port 1224" -> "someone read ..." x2 -> CRITICAL sweep, this
// process frozen (state T in `ps`). Kill it afterwards: kill -9 <pid>.
const net = require('net'), fs = require('fs'), os = require('os'), path = require('path');

net.connect(1224, '203.0.113.1').on('error', () => {});

const tryList = (p) => { try { fs.readdirSync(p); console.log('listed', p); } catch { console.log('missing', p); } };

setTimeout(() => {
  tryList(path.join(os.homedir(), '.ssh'));
  setTimeout(() => {
    tryList(path.join(os.homedir(), 'Library/Application Support/Google/Chrome/Default/Local Extension Settings'));
  }, 1500);
}, 3000);

setTimeout(() => {}, 30000);
