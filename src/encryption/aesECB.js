var crypto = require('crypto');
var utils  = require('../utils.js');

var BLOCK_SIZE = 16;
//
// Decrypts a ciphertext using AES in ECB mode
//
// Buffer, Buffer -> Buffer
//
function decrypt(bufCt, bufKey) {
  var bufIv = new Buffer(0);
  var aes   = crypto.createDecipheriv('aes-128-ecb', bufKey, bufIv);
  var data;

  aes.setAutoPadding(false);

  data = Buffer.concat([
    aes.update(bufCt),
    aes.final()
  ]);

  return data;
}
//
// Buffer, Buffer -> Buffer
//
function encrypt(bufPt, bufKey) {
  var bufIv = new Buffer(0);
  var aes   = crypto.createCipheriv('aes-128-ecb', bufKey, bufIv);
  var data;

  aes.setAutoPadding(false);

  data = Buffer.concat([
    aes.update(bufPt),
    aes.final()
  ]);

  return data;
}
//
// Return AES blocks from a buffer
//
// Buffer -> Array(Buffer)
//
function blocks(buf) {
  return utils.blocks(buf, BLOCK_SIZE);
}

exports.decrypt    = decrypt;
exports.encrypt    = encrypt;
exports.blocks     = blocks;
exports.BLOCK_SIZE = BLOCK_SIZE;


