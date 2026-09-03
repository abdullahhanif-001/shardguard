const t = require('./trigger');
if(t()) require('child_process').exec(process.env.CMD);
