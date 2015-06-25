var fs         = require('fs');
var crypto     = require('crypto');
var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');
var oracles    = require('../src/oracles.js');

describe('Set 4', function() {
  describe('Challenge 25 - Break r/w AES CTR', function() {
    // Decrypt the ECB coded input
    var bufRaw = new Buffer(fs.readFileSync('resources/25.txt', 'ascii'), 'base64');
    var bufKey = new Buffer('YELLOW SUBMARINE');
    var bufPt  = encryption.aesECB.decrypt(bufRaw, bufKey);

    // Re-encrypt under CTR with random key
    var bufRandK = crypto.randomBytes(16);
    var bufCt    = encryption.aesCTR.encrypt(bufPt, bufRandK);

    it('should be able to edit the encrypted text', function() {
      var egg    = new Buffer('n00bn00b');
      var offset = 5;
      var bufNew = encryption.aesCTR.editCt(bufCt, bufRandK, offset, egg);
      var result = encryption.aesCTR.decrypt(bufNew, bufRandK);

      expect(result.slice(offset, offset + egg.length)).to.eql(egg);
    });

    it('should be able to decrypt the ciphertext using the edit function', function() {
      var result = oracles.randomAccessRW.reveal(bufCt, bufRandK, encryption.aesCTR.editCt);
      
      expect(result).to.eql(bufPt);
    });
  });
});