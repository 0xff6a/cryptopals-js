var utils = require('../utils.js');
//
// Encrypts a ciphertext using single char XOR with unknown key
//
// String (ascii), String (ascii) -> String (hex)
//
function encrypt(plaintext, key) {
  var bufKey = new Buffer(key);
  var bufPt  = new Buffer(plaintext);
  var buf    = new Buffer(plaintext.length);
  var keyLen = bufKey.length;

  for (var i = 0; i <= bufPt.length; i++) {
    buf[i] = bufPt[i] ^ bufKey[i % keyLen];
  }

  return buf.toString('hex');
}

exports.encrypt = encrypt;