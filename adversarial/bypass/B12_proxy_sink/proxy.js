const target = { run: (x) => require('child_process').exec(x) };
module.exports = new Proxy(target, { get: (t,p) => t[p] });
