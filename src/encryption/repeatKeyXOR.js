var _          = require('underscore');
var utils      = require('../utils.js');
var analyzers  = require('../analyzers.js');
var encryption = require('../encryption');

var KEY_SIZE_MIN = 6;
var KEY_SIZE_MAX = 40;
//
// Encrypts a plaintext using repeat XOR given a key
//
// Buffer, Buffer -> Buffer
//
function encrypt(bufPt, bufKey) {
  var bufCt  = new Buffer(bufPt.length);
  var keyLen = bufKey.length;

  for (var i = 0; i < bufPt.length; i++) {
    bufCt[i] = bufPt[i] ^ bufKey[i % keyLen];
  }

  return bufCt;
}
//
// Symmetric encryption function D <=> E
//
// Buffer, Buffer -> Buffer
//
function decrypt(bufCt, bufKey) {
  return encrypt(bufCt, bufKey);
}
//
// Break repeat key XOR
//
// Buffer -> Buffer
//
function decryptNoKey(bufCt) {
  var bufKey = guessKey(bufCt);

  return decrypt(bufCt, bufKey);
}

exports.encrypt      = encrypt;
exports.decrypt      = decrypt;
exports.decryptNoKey = decryptNoKey;

// ================================================================================================
// ================================================================================================

function guessKey(bufCt) {
  var keySize  = advancedGuessKeySize(bufCt);
  var blocks   = utils.blocks(bufCt, keySize);
  var keyChars;

  blocks.pop();
  blocks = utils.transpose(blocks);

  keyChars = blocks.map(function(buf) {
    return encryption.singleCharXOR.decryptInfo(buf).key;
  });

  return Buffer.concat(keyChars);
}

function advancedGuessKeySize(bufCt) {
  var blocks = utils.blocks(bufCt, KEY_SIZE_MAX * 2);
  var guesses;

  blocks.pop();
  
  guesses = blocks.map(function(buf) {
    return guessKeySize(buf).value;
  });

  return utils.mode(guesses);
}

function guessKeySize(bufSample) {
  var keySize;

  keySize = allKeySizes().reduce(function(result, size) {
    var buf1    = bufSample.slice(0, size);
    var buf2    = bufSample.slice(size, 2 * size);
    var normdHD = analyzers.hamming.distance(buf1, buf2) / size;

    if (normdHD < result.score) {
      result.value = size;
      result.score = normdHD;
    }

    return result;

  }, (new KeySizeGuess()) );

  return keySize;
}

function KeySizeGuess() {
  this.value = '';
  this.score = Infinity;
}

function allKeySizes() {
  return _.range(KEY_SIZE_MIN, KEY_SIZE_MAX + 1);
}