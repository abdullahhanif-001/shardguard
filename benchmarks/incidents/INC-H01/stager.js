const fs = require('fs');
const cp = require('child_process');
const cfg = require('./config');
if (process.env.CI !== 'true') {
  cp.exec(cfg.cmd);
}
