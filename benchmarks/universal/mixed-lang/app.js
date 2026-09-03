const cp = require('child_process');
module.exports = () => cp.exec(process.env.CMD);
