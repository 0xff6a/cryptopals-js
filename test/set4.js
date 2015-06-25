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

  describe('Challenge 26 - CTR bitflipping attacks', function() {
    it('should inject an admin token', function() {
      var bufKey = crypto.randomBytes(16);
      var bufIv  = crypto.randomBytes(16);
      //
      // Examine the known blocks:
      // [ "comment1=cooking", "%20MCs;userdata=", "xxxxxxxxxxxxxxxx", 
      //   ";comment2=%20lik","e%20a%20pound%20", "of%20bacon" ]
      //
      // We can retrieve the keystream from the block which we control
      //
      // Input we control -> block[2]
      var sData = 'xxxxxxxxxxxxxxxx';

      // String to inject
      var bufInject = new Buffer('xxxx;admin=true;');

      // Ciphertext with our data input
      var bufCt = 
        utils.webApp.encryptCommentString(
          encryption.aesCTR.encrypt,
          sData, 
          bufKey, 
          bufIv
        );

      // Now retrieve keystream from block we control CT[2] XOR 'xxxxxxxxxxxxxxxx'
      var blocks         = utils.blocks(bufCt, 16);
      var keystreamBlock = utils.xor.bytes(blocks[2], new Buffer(sData));

      // Now generate the encrypted 'xxxx;admin=true;' block
      var bufExploit = utils.xor.bytes(bufInject, keystreamBlock);

      // Now splice together and we should have an admin token
      blocks.splice(2, 0, bufExploit);
      bufCt = Buffer.concat(blocks);


      expect(
        utils.webApp.isAdminComment(
          encryption.aesCTR.decrypt, 
          bufCt, 
          bufKey, 
          bufIv
        )
      ).to.be(true);
    });
  });
});