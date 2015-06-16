var fs         = require('fs');
var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');
var analyzers  = require('../src/analyzers.js');
var oracles    = require('../src/oracles.js');

describe('Set 2', function() {
  describe('Challenge 9  - PKCS7 padding', function() {
    var blockSize = 20;
    var bufPad    = new Buffer('YELLOW SUBMARINE\x04\x04\x04\x04');
    var bufRaw    = new Buffer('YELLOW SUBMARINE');

    it('should add PKCS7 padding', function() {
      expect(utils.pkcs7.pad(bufRaw, blockSize)).to.eql(bufPad);
    });

    it('should strip PKCS7 padding', function() {
      expect(utils.pkcs7.strip(bufPad, blockSize)).to.eql(bufRaw);
    });
  });

  describe('Challenge 10 - Implement AES in CBC mode', function() {
    it('should decrypt a ciphertext given key and IV', function() {
      var data   = new Buffer(fs.readFileSync('resources/10.txt', 'ascii'), 'base64');
      var bufKey = new Buffer('YELLOW SUBMARINE');
      var bufIv  = new Buffer(16).fill('\x00');
      var result = 
        encryption
          .aesCBC.decrypt(data, bufKey, bufIv)
          .toString('ascii')
          .slice(0, 150);
      
      expect(result).to.eql(
        "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while" +
        " the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my" +
        " DJ Deshay cuttin\' all "
      );
    });
  });
});
