const cp = require('child_process');
const cfg = require('./config');
module.exports = { run: () => cp.exec(cfg.cmd) };
