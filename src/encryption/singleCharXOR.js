var utils     = require('../utils.js');
var analyzers = require('../analyzers.js');
//
// Decrypts a ciphertext using single char XOR with unknown key
//
// String (hex) -> Result
//
function decrypt(ciphertext) {
  var buf = new Buffer(ciphertext, 'hex');
  var len = buf.length;
  var res = new Result();
  var candidate;
  var key;
  var score;

  for (var k = 0; k < 256; k++) {
    key       = buildKey(k, len);
    candidate = utils.xor.bytes(buf, key).toString('ascii');
    score     = analyzers.textScorer.calculate(candidate);

    if (score < res.score) {
      res.score     = score;
      res.key       = key;
      res.plaintext = candidate;
    }
  }

  return res;
}

function Result() {
  this.key       = '';
  this.plaintext = '';
  this.score     = Infinity;
}

function buildKey(charCode, len) {
  var buf = new Buffer(len);

  buf.fill(String.fromCharCode(charCode));

  return buf;
}

exports.decrypt = decrypt;