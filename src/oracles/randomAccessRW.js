var utils = require('../utils.js');
//
// Simulate random access read/write decryption
//
// Using CT = PT XOR K, we supply PT and receive CT 
// -> K = CT XOR PT
//
// Buffer, Buffer, Function -> Buffer
//
function reveal(bufCt, bufKey, fEdit) {
  var size       = bufCt.length;
  var bufExploit = new Buffer(size).fill('\x41');
  var bufTmp     = fEdit(bufCt, bufKey, 0, bufExploit);
  var keyStream  = utils.xor.bytes(bufTmp, bufExploit);

  return utils.xor.bytes(keyStream, bufCt);
}

exports.reveal = reveal;