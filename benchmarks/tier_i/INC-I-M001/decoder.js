const enc = require('./encoder');
module.exports = function decode(b) { return Buffer.from(b, 'base64').toString(); };
