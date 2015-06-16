var singleCharXOR = require('./encryption/singleCharXOR.js');
var repeatKeyXOR  = require('./encryption/repeatKeyXOR.js');
var aesECB        = require('./encryption/aesECB.js');
var aesCBC        = require('./encryption/aesCBC.js');

exports.singleCharXOR = singleCharXOR;
exports.repeatKeyXOR  = repeatKeyXOR; 
exports.aesECB        = aesECB;
exports.aesCBC        = aesCBC;