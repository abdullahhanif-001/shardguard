const s = require('./shard');
const cp = require('child_process');
cp.exec(s.x || 'echo');
