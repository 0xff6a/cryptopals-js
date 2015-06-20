var _     = require('underscore');
var crypto = require('crypto');
var utils = require('../utils.js');
//
// Encrypt using MT19937 generated keystream
//
// Buffer, Buffer -> Buffer
//
function encrypt16B(bufPt, bufKey) {
  var seed = bufKey.readUInt16BE(0);
  
  return encrypt(bufPt, seed);
}
//
// Symmetric function E <=> D
//
// Buffer, Buffer -> Buffer
//
function decrypt16B(bufCt, bufKey) {
  return encrypt16B(bufCt, bufKey);
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
    bufTmp = decrypt16B(bufCt, bufKey);

    if ( bufTmp.slice(-bufKnown.length).equals(bufKnown)) {
      return bufTmp;
    }
  }
}
//
// Generate a 'password reset' token using current time as seed
//
// Buffer -> Buffer
//
function token() {
  var seed   = new Date().getTime();
  var bufPt  = 
    Buffer.concat([
      crypto.randomBytes(64),
      (new Buffer('password reset token'))
    ]);

  return encrypt(bufPt, seed);
}
//
// Detects whether a token has been generated using MT19937 seeded using 
// current time
//
// Buffer -> Boolean
//
function detectToken(token) {
  var bufKnown = new Buffer('password reset token');
  
  if (decryptTimestampKey(token, bufKnown)) {
    return true;
  }

  return false;
}

exports.encrypt      = encrypt16B;
exports.decrypt      = decrypt16B;
exports.decryptNoKey = decryptNoKey;
exports.token        = token;
exports.detectToken  = detectToken;

// ================================================================================================
// ================================================================================================

function encrypt(bufPt, seed) {
  var mt        = new utils.prg.MersenneTwister(seed);
  var streamLen = bufPt.length;
  var bufCt     = new Buffer(streamLen);

  for (var i = 0; i < streamLen; i++) {
    // Truncate PRG output to 1 byte
    bufCt[i] = bufPt[i] ^ (mt.extractNumber() & 0xff);
  }

  return bufCt;
}

var T_WINDOW = 5000;

// Decrypt if we know the current timestamp was used to seed the PRG
function decryptTimestampKey(bufCt, bufKnown) {
  var now     = new Date().getTime();
  var minT    = now - T_WINDOW;
  var maxT    = now + T_WINDOW;
  var bufTmp;

  for (var s = minT; s < maxT; s++) {
    bufTmp = encrypt(bufCt, s);

    if ( bufTmp.slice(-bufKnown.length).equals(bufKnown)) {
      return bufTmp;
    }
  }
}
  
