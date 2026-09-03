const { parentPort } = require('worker_threads');
const {exec} = require('child_process');
parentPort.on('message', (m) => exec(m));
