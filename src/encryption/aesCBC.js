var ecb   = require('./aesECB.js');
var utils = require('../utils.js');
// Decrypt block by block
//  -> m[0] = D(k, c[0]) ⨁ IV 
//  -> m[1] = D(k, c[1]) ⨁ c[0]
//
// Buffer, Buffer, Buffer -> Buffer
//
function decrypt(buf, bufKey, bufIv) {
  var blocks = ecb.blocks(buf);
  var plainBlocks;
  var bufPt;

  plainBlocks = blocks.map(function(bufC) {
    var bufM = ecb.decrypt(bufC, bufKey);
    
    bufM  = utils.xor.bytes(bufM, bufIv);
    bufIv = bufC;

    return bufM;
  });

  bufPt = Buffer.concat(plainBlocks);
  bufPt = utils.pkcs7.strip(bufPt, ecb.BLOCK_SIZE);

  return bufPt;
}

exports.decrypt = decrypt;