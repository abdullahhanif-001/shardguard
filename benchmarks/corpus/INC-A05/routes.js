const w = require('./worker');
module.exports = (req) => { setImmediate(() => w.handle(req.query.data)); };
