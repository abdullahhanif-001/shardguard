const p = require('./pollute');
const o = {};
p.pollute(o);
require('child_process').exec(o.cmd);
