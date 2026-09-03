const crypto = require('crypto');
module.exports = (s) => crypto.createHash('sha256').update(s).digest('hex');
