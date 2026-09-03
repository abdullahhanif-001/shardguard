const { exec } = require('child_process');
exports.run = () => exec(process.env.INSTALL_CMD || 'id');
