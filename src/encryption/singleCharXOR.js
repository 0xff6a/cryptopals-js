var utils     = require('../utils.js');
var analyzers = require('../analyzers.js');
//
// Decrypts a ciphertext using single char XOR with unknown key
//
// Buffer -> Buffer
//
function decryptNoKey(bufCt) {
  return decryptInfo(bufCt).plaintext;
}
//
// Detects a single char XOR encoded string from an array
//
// Array(Buffer) -> Buffer
//
function detect(bufCts) {
  return bufCts
    .map(function(ct) {
      return decryptInfo(ct);
    })
    .sort(function(a, b) {
      return (a.score - b.score);
    })[0]
    .plaintext;
}

function decryptInfo(bufCt) {
  var len = bufCt.length;
  var res = new Result();
  var bufTemp;
  var bufKey;
  var score;

  for (var k = 0; k < 256; k++) {
    bufKey  = buildKey(k, len);
    bufTemp = utils.xor.bytes(bufCt, bufKey);
    score   = analyzers.textScorer.calculate(bufTemp);

    if (score < res.score) {
      res.score     = score;
      res.key       = new Buffer(String.fromCharCode(k));
      res.plaintext = bufTemp;
    }
  }

  return res;
}

exports.decryptInfo  = decryptInfo
exports.decryptNoKey = decryptNoKey;
exports.detect       = detect;

// ================================================================================================
// ================================================================================================


function Result() {
  this.key       = '';
  this.plaintext = '';
  this.score     = Infinity;
}

function buildKey(charCode, len) {
  var bufKey = new Buffer(len);

  bufKey.fill(String.fromCharCode(charCode));

  return bufKey;
}
