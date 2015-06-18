var fs         = require('fs');
var encryption = require('../src/encryption.js');
var utils      = require('../src/utils.js');

// ================================================================================================
// Shared Helpers for Challenges 19 & 20
// ================================================================================================

var ctr = (function() {

  var methods = {};

  // Private Variables
  var bufNonce = new Buffer(8).fill('\x00');

  // Public Methods
  methods.decryptCtArray = function(arrCt, keyStream) {
    var pts = 
      arrCt.map(function(bufCt) {
        return decrypt(bufCt, keyStream).toString();
      });

    return pts;

    function decrypt(ct, keyStream) {
      return utils.xor.bytes(ct, keyStream.slice(0, ct.length));
    }
  };

  methods.encryptFromB64File = function(filepath, bufKey) {
    var data = 
      fs.readFileSync(filepath)
        .toString()
        .split('\n')
        .map(function(pt) {
          return encrypt(pt, bufKey);
        });

    return data;

    function encrypt(pt, bufKey) {
      var bufPt = new Buffer(pt, 'base64');

      return encryption.aesCTR.encrypt(bufPt, bufKey, bufNonce);
    }
  };

  return methods;

}());

// ================================================================================================
// ================================================================================================

exports.ctr = ctr;