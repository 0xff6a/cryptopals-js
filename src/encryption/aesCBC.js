var crypto = require('crypto');
var aes    = require('./aesECB.js');
var utils  = require('../utils.js');
// Encrypt block by block
//  -> c[0] = E(k, m[0] ⨁ IV)
//  -> c[1] = E(k, m[1] ⨁ c[0])
//  -> ...
//
// Buffer, Buffer, Buffer -> Buffer
//
function encrypt(buf, bufKey, bufIv) {
  var blocks = aes.blocks(utils.pkcs7.padAES(buf));
  var cipherBlocks;

  cipherBlocks = blocks.map(function(bufM) {
    var bufC;

    bufM  = utils.xor.bytes(bufM, bufIv);
    bufC  = processBlock(bufM, bufKey, crypto.createCipheriv);
    bufIv = bufC;

    return bufC;
  });

  return Buffer.concat(cipherBlocks);
}

// Decrypt block by block
//  -> m[0] = D(k, c[0]) ⨁ IV 
//  -> m[1] = D(k, c[1]) ⨁ c[0]
//  -> ...
//
// Buffer, Buffer, Buffer -> Buffer
//
function decrypt(buf, bufKey, bufIv) {
  var blocks   = aes.blocks(buf);
  var plainBlocks;
  var bufPt;

  plainBlocks = blocks.map(function(bufC) {
    var bufM = processBlock(bufC, bufKey, crypto.createDecipheriv);
    
    bufM  = utils.xor.bytes(bufM, bufIv);
    bufIv = bufC;

    return bufM;
  });

  bufPt = Buffer.concat(plainBlocks);
  bufPt = utils.pkcs7.stripAES(bufPt);

  return bufPt;
}

exports.decrypt = decrypt;
exports.encrypt = encrypt;

// ================================================================================================
// ================================================================================================

function processBlock(buf, bufKey, cipherBuilder) {
  var cipher = cipherBuilder('aes-128-ecb', bufKey, (new Buffer(0)));
  
  cipher.setAutoPadding(false);

  return Buffer.concat([
    cipher.update(buf),
    cipher.final()
  ]);
}