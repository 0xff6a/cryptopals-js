var utils = require('../utils.js');
var _     = require('underscore');

//
// Encrypt using MT19937 generated keystream
//
// Buffer, Buffer -> Buffer
//
function encrypt(bufPt, bufKey) {
  var seed      = bufKey.readUInt16BE(0);
  var mt        = new utils.prg.MersenneTwister(seed);
  var streamLen = bufPt.length;
  var bufCt     = new Buffer(streamLen);

  for (var i = 0; i < streamLen; i++) {
    // Truncate PRG output to 1 byte
    bufCt[i] = bufPt[i] ^ (mt.extractNumber() & 0xff);
  }

  return bufCt;
}
//
// Symmetric function E <=> D
//
// Buffer, Buffer -> Buffer
//
function decrypt(bufCt, bufKey) {
  return encrypt(bufCt, bufKey);
}
//
// Break MT19937 encryption given a known plaintext segment
// by bruteforcing the seed (assumes segment at the end of ciphertext)
//
// Buffer, Buffer -> Buffer
//
function decryptNoKey(bufCt, bufKnown) {
  var bufKey = new Buffer(2);
  var bufTmp;

  for (var s = 0; s < Math.pow(2, 16); s++) {
    bufKey.writeUInt16BE(s);
    bufTmp = decrypt(bufCt, bufKey);

    if ( bufTmp.slice(-bufKnown.length).equals(bufKnown)) {
      return bufTmp;
    }
  }
}

exports.encrypt      = encrypt;
exports.decrypt      = decrypt;
exports.decryptNoKey = decryptNoKey;