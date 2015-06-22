var crypto     = require('crypto');
var encryption = require('../encryption.js');

var BLOCK_SIZE = 16;

function BlackBox(bufT) {
  this.target = bufT;
  this.key    = crypto.randomBytes(BLOCK_SIZE);
}

BlackBox.prototype.encrypt = function(bufPt) {
  bufPt = Buffer.concat([bufPt, this.target]);

  return encryption.aesECB.encrypt(bufPt, this.key);
};

BlackBox.prototype.bytesLength = function() {
  return this.encrypt(new Buffer(0)).length;
};

exports.BlackBox = BlackBox;