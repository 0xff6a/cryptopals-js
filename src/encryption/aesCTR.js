var aes   = require('./aesECB.js');
var utils = require('../utils.js');

// NOTE nonce and ctr are in little-endian format

// Decrypt block by block
// -> m[0] = F(k, nonce || ctr) ⨁ c[0]
// -> m[1] = F(k, nonce || ctr + 1) ⨁ c[1]
// -> .....
//
// Buffer, Buffer, Buffer -> Buffer
//
function decrypt(bufCt, bufKey, bufNonce) {
  var bufCtr = new Buffer(8).fill('\x00');
  var blocks = aes.blocks(bufCt);
  var plainBlocks;

  plainBlocks = blocks.map(function(bufC) {
    var bufF = aes.encrypt(Buffer.concat([ bufNonce, bufCtr ]), bufKey);

    bufC   = utils.xor.bytes(bufF.slice(0, bufC.length), bufC);
    bufCtr = incrementCtr(bufCtr);

    return bufC;
  });

  return Buffer.concat(plainBlocks);
}
//
// Symmetric function E <=> D
//
//
function encrypt(bufPt, bufKey, bufNonce) {
  return decrypt(bufPt, bufKey, bufNonce);
}
// Buffer -> Buffer
//
function incrementCtr(bufCtr) {
  for (var i = 0; i < bufCtr.length; i++) {
    if (bufCtr[i] !== 255) {
      bufCtr[i]++;
      break;
    }
  }

  return bufCtr;
}

exports.decrypt            = decrypt;
exports.encrypt            = encrypt;
exports.littleEndIncrement = incrementCtr;

// ================================================================================================
// ================================================================================================

