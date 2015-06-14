var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');

describe('Set 1', function() {
  describe('Challenge 1', function() {
    it('should convert hex to base64', function() {
      var hexString = 
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206" + 
      "120706f69736f6e6f7573206d757368726f6f6d";
      var b64String = 
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
      var buf = new Buffer(hexString, 'hex');

      expect(buf.toString('base64')).to.eql(b64String);
    });
  });

  describe('Challenge 2', function() {
    it('should XOR two equal length hex strings', function() {
      var hex1   = "1c0111001f010100061a024b53535009181c";
      var hex2   = "686974207468652062756c6c277320657965";
      var result = "746865206b696420646f6e277420706c6179";

      expect(utils.xor.hex(hex1, hex2)).to.eql(result);
    });
  });

  describe('Challenge 3', function() {
    it('should decrypt single char XOR', function() {
      var ciphertext = 
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
      var plaintext = 
      "hello";

      expect(encryption.singleCharXOR.decrypt(ciphertext)).to.eq(plaintext);
    });
  });
});
