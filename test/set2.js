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
      
    });
  });
});
