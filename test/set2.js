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
    var data   = new Buffer(fs.readFileSync('resources/10.txt', 'ascii'), 'base64');
    var bufKey = new Buffer('YELLOW SUBMARINE');
    var bufIv  = new Buffer(16).fill('\x00');
    var bufPt  = encryption.aesCBC.decrypt(data, bufKey, bufIv);

    it('should decrypt a ciphertext given key and IV', function() {
      var plaintext = bufPt.toString('ascii').slice(0, 150);

      expect(plaintext).to.eql(
        "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while" +
        " the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my" +
        " DJ Deshay cuttin\' all "
      );
    });

    it('should encrypt a plaintext given key and IV', function() {
      expect(encryption.aesCBC.encrypt(bufPt, bufKey, bufIv)).to.eql(data);
    });
  });

  describe('Challenge 11 - Implement an ECB/CBC detection oracle', function() {
    it('should detect whether a ciphertext was encrypted with ECB or CBC', function() {
      var bufPt  = fs.readFileSync('resources/plain.txt');
      var result = oracles.aes.encryptRandom(bufPt);
  
      expect(oracles.aes.mode(result.ct)).to.eql(result.mode);
    });
  });

  describe('Challenge 12 - Byte-at-a-time ECB decryption', function() {
    it.skip('should decrypt an AES ECB string from a black box encoder', function() {
      var target = 
        new Buffer(
          'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' + 
          'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' +
          'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        );
      var box     = new utils.o.BlackBox(target);
      var content = oracles.aes.revealContent(box);

      expect(content).to.eql(
        "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe " +
        "girlies on standby waving just to say hi\nDid you stop? No, I just " +
        "drove by\n\x06\x06\x06\x06\x06\x06"
      );
    });
  });

  describe('Challenge 13 - ECB cut and paste', function() {
    var email = 'foo@bar.com';

    it('should be able to parse a structured cookie string', function() {
      expect(utils.webApp.kvParse("foo=bar&baz=qux&zap=zazzle")).to.eql({
        foo: 'bar',
        baz: 'qux',
        zap: 'zazzle'
      });
    });
    
    it('should be able to create a user profile hash from an email', function() {
      expect(utils.webApp.profileFor(email)).to.eql('email=foo@bar.com&uid=10&role=user');
    });
         
    it('should not allow encoding metacharacters in a profile', function() {
      var hack = 'foo@bar.com&role=admin';

      expect(utils.webApp.profileFor(hack)).to.eql('email=foo@bar.com&uid=10&role=user');
    });
  });
});
