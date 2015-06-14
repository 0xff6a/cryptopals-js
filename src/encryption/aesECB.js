var crypto = require('crypto');
//
// Decrypts a ciphertext using AES in ECB mode
//
// Buffer, Buffer -> Buffer
//
function decrypt(bufPt, bufKey) {
  var bufIv = new Buffer(0);
  var aes   = crypto.createDecipheriv('aes-128-ecb', bufKey, bufIv);
  var data;

  aes.setAutoPadding(false);

  data = Buffer.concat([
    aes.update(bufPt),
    aes.final()
  ]);

  return data;
}

exports.decrypt = decrypt;

// ================================================================================================
// ================================================================================================
