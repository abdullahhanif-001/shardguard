const mid = require('./b');
const fs = require('fs');
fs.writeFileSync('/tmp/out', mid());
