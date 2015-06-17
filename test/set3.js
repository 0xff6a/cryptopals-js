var fs         = require('fs');
var crypto     = require('crypto');
var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');

describe('Set 3', function() {
  describe('Challenge 18  - Implement AES in CTR mode', function() {
    var bufCt  = 
      new Buffer('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==', 'base64');
    var bufKey    = new Buffer('YELLOW SUBMARINE');
    var bufNonce  = new Buffer(8).fill('\x00');
    var plaintext = encryption.aesCTR.decrypt(bufCt, bufKey, bufNonce);

    it('should increment a little endian ctr', function() {
      var bufCtr = new Buffer(8).fill('\x00', 'ascii');
      var once   = encryption.aesCTR.littleEndIncrement(bufCtr);
      var many   = new Buffer(8).fill('\x00', 'ascii');

      expect(once).to.eql(new Buffer('\x01\x00\x00\x00\x00\x00\x00\x00', 'ascii'));

      for (var i =0; i < 256; i++) {
        many = encryption.aesCTR.littleEndIncrement(bufCtr);
      }
      expect(many).to.eql(new Buffer('\xff\x02\x00\x00\x00\x00\x00\x00', 'ascii'));
    });

    it('should decrypt a AES::CTR encrypted ciphertext given nonce and key', function() {
      expect(plaintext).to.eql(new Buffer('Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby '));
    });

    it('should encrypt in AES::CTR mode', function() {
      expect(encryption.aesCTR.encrypt(plaintext, bufKey, bufNonce)).to.eql(bufCt);
    });
  });

  describe('Challenge 19 - break fixed nonce CTR', function() {
    var bufKey   = new Buffer('0f3bc4ed8e87a792a47d16657538d267', 'hex');
    var bufNonce = new Buffer(8).fill('\x00');

    function encrypt(pt) {
      var bufPt = new Buffer(pt, 'base64');

      return encryption.aesCTR.encrypt(bufPt, bufKey, bufNonce);
    }

    function decrypt(ct, keyStream) {
      return utils.xor.bytes(ct, keyStream.slice(0, ct.length));
    }

    it('should decrypt a set of ciphertexts encrypted under a fixed nonce', function() { 
      var data = 
        fs.readFileSync('resources/19.txt')
          .toString()
          .split('\n')
          .map(encrypt);

      var keyGuess = encryption.aesCTR.guessKeyStream(data);
      var pts = 
        data.map(function(bufCt) {
          return decrypt(bufCt, keyGuess).toString();
        });

      // Not 100% decrypted but that comes in the next challenge
      expect(pts[3]).to.eql('eighteenth-cenvury houses.');
    });
  });
});
