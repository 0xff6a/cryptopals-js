var _          = require('underscore');
var encryption = require('../encryption.js');
var crypto     = require('crypto');

var BLOCK_SIZE = encryption.aesECB.BLOCK_SIZE;
//
// Decrypts the target string encrypted in a Black Box encoder
//
// BlackBox -> Buffer
//
function revealContent(blackBox) {
  // Discover block size
  var blockSize = getBlockSize(blackBox);

  // Confirm ECB encrypted
  validateECB(blackBox);
  
  // Decrypt byte-by-byte
  return revealBytes(blackBox, blockSize);
}
//
// Returns whether a ciphertext has been ECB encrypted
//
// Buffer -> Boolean
//
function isECB(buf) {
  var blocks = 
    encryption.aesECB
      .blocks(buf)
      .map( function(b) { 
        return b.toString('hex'); 
      });

  return (_.uniq(blocks).length !== blocks.length);
}
//
// Returns whether a ciphertext has been encrypted in ECB or CBC
//
// Buffer -> String
//
function mode(bufPt) {
  return (isECB(bufPt) ? 'ECB' : 'CBC');
}
//
// Randomly encrypts a buffer using either ECB or CBC
//
// Buffer -> Object(String, Buffer)
//
function encryptRandom(bufPt) {
  var bufKey = crypto.randomBytes(BLOCK_SIZE);
  var bufIv  = crypto.randomBytes(BLOCK_SIZE);
  var result = {};

  result.mode = randomMode();

  if (result.mode === 'ECB') {
    result.ct = encryption.aesECB.encrypt(bufPt, bufKey);
  } else {
    result.ct = encryption.aesCBC.encrypt(bufPt, bufKey, bufIv);
  }

  return result;
}

exports.isECB         = isECB;
exports.encryptRandom = encryptRandom;
exports.mode          = mode;
exports.revealContent = revealContent;

// ================================================================================================
// ================================================================================================

function getBlockSize(blackBox) {
  var initSize = blackBox.bytesLength();
  var ctr      = 1;
  var size;
  var bufT;

  while (true) {
    bufT = new Buffer(ctr).fill('A');
    size = blackBox.encrypt(bufT).length;

    if (size !== initSize) {
      return (size - initSize);
    }

    ctr++;
  }
}

function validateECB(blackBox) {
  var bufTest = new Buffer(2 * BLOCK_SIZE);

  bufTest.fill('A');

  if (!isECB(blackBox.encrypt(bufTest))) {
    throw new Error('Uknown ciphertext is not AES::ECB encrypted');
  }
}

function revealBytes(blackBox, blockSize) {
  var knownBytes = [];
  var targetSize = blackBox.bytesLength();

  for (var i = 0; i < targetSize; i++) {
    var bufPt = new Buffer(targetSize - i - 1).fill('A');
    var dict  = {};
    var ct    = blackBox
                  .encrypt(bufPt)
                  .slice(0, targetSize)
                  .toString();
    
    for (var g = 0; g < 256; g++) {
      var clear = Buffer.concat([
                    bufPt,
                    (new Buffer(knownBytes)), 
                    (new Buffer([g]))
                  ]);

      var dictKey = blackBox
                      .encrypt(clear)
                      .slice(0, targetSize)
                      .toString();

      dict[dictKey] = g;
    }

    knownBytes.push(dict[ct]);
  }

  return (new Buffer(knownBytes));
}

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

function randomMode() {
  return MODES[Math.round(Math.random())];
}

function randomBytes() {
  return crypto.randomBytes(Math.random(10));
}