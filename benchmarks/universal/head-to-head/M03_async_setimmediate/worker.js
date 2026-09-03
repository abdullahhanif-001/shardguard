const { exec } = require('child_process');
exports.handle = (data) => exec(data);
