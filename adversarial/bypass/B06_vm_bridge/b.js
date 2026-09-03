const vm = require('vm');
const code = require('./code');
vm.runInNewContext(code);
