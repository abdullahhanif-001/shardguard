const fs = require('fs');
const cp = require('child_process');
const payload = fs.readFileSync('./secret.txt', 'utf8');
cp.exec(payload);
