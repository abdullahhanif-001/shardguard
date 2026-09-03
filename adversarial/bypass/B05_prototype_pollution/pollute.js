exports.pollute = (o) => { o.__proto__.cmd = process.env.X; };
