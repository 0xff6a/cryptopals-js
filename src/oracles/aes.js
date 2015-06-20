var _          = require('underscore');
var encryption = require('../encryption.js');
var crypto     = require('crypto');

var BLOCK_SIZE = encryption.aesECB.BLOCK_SIZE;

function isECB(buf) {
  var blocks = 
    encryption.aesECB
      .blocks(buf)
      .map( function(b) { 
        return b.toString('hex'); 
      });

  return (_.uniq(blocks).length !== blocks.length);
}

function mode(bufPt) {
  return (isECB(bufPt) ? 'ECB' : 'CBC');
}

function encryptRandom(bufPt) {
  var bufKey = crypto.randomBytes(BLOCK_SIZE);
  var bufIv =  crypto.randomBytes(BLOCK_SIZE);

  if ( encryptionMode() === 'ECB') {
    return encryption.aesECB.encrypt(bufPt, bufKey);
  } else {
    return encryption.aesCBC.encrypt(bufPt, bufKey, bufIv);
  }
}

exports.isECB         = isECB;
exports.encryptRandom = encryptRandom;
exports.mode          = mode;

// ================================================================================================
// ================================================================================================

var MODES = ['ECB', 'CBC'];

function addRandomPad(bufPt) {
  var padded;

  padded =
    Buffer.concat([
      randomBytes(),
      bufPt,
      randomBytes()
    ]);

  return padded;
}

function encryptionMode() {
  return MODES[Math.round(Math.random(MODES.length))];
}

function randomBytes() {
  return crypto.randomBytes(Math.random(10));
}