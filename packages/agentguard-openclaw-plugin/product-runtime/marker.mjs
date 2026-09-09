import fs from 'node:fs';
const p = 'command-marker.txt';
const fd = fs.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW, 0o600);
try { fs.writeSync(fd, 'isolated command executed\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
process.stdout.write(JSON.stringify({ok: true, marker: p}) + '\n');
