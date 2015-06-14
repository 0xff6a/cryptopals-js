var fs         = require('fs');
var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');
var analyzers  = require('../src/analyzers.js');

describe('Set 1', function() {
  describe('Challenge 1 - Hex to Base64', function() {
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

  describe('Challenge 2 - XOR hex strings', function() {
    it('should XOR two equal length hex strings', function() {
      var hex1   = "1c0111001f010100061a024b53535009181c";
      var hex2   = "686974207468652062756c6c277320657965";
      var result = "746865206b696420646f6e277420706c6179";

      expect(utils.xor.hex(hex1, hex2)).to.eql(result);
    });
  });

  describe('Challenge 3 - single char XOR', function() {
    it('should evaluate the frequency of characters in a string', function() {
      expect(analyzers.textScorer.absoluteFreq('abbcccddddeeeee')).to.eql({
        "a": 1, "b": 2, "c": 3, "d": 4, "e": 5
      });
    });

    it('should score strings based on character frequency vs average', function() {
      var english = analyzers.textScorer.calculate('hello my name is jeremy');
      var bad     = analyzers.textScorer.calculate('hello my name is £&(*fhcsjkbv');
      var worse   = analyzers.textScorer.calculate('sml£&0m,c');

      expect([bad, english, worse].sort()).to.eql([english, bad, worse]);
    });

    it('should decrypt single char XOR', function() {
      var ciphertext = 
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
      var plaintext = 
      "Cooking MC\'s like a pound of bacon";
      var decrypted = encryption.singleCharXOR.decrypt(ciphertext).plaintext;

      expect(decrypted).to.eql(plaintext);
    });
  });

  describe('Challenge 4 - detect single char XOR (SKIP FOR SPEED)', function() {
    it.skip('should detect single char XOR from a set of sample strings', function() {
      var data   = fs.readFileSync('resources/4.txt');
      var result = 
        data
          .toString()
          .split("\n")
          .map(function(ct) {
            return encryption.singleCharXOR.decrypt(ct);
          })
          .sort(function(a, b) {
            return (a.score - b.score);
          })[0]
          .plaintext;

      expect(result).to.eql("Now that the party is jumping\n");
    });
  });

  describe('Challenge 5 - implement repeat key XOR', function() {
    it('should encrypt under repeat key XOR', function() {
      var key = 'ICE';
      var plaintext = 
      "Burning 'em, if you ain't quick and nimble\n" +
      "I go crazy when I hear a cymbal";
      var ciphertext = 
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

      expect(encryption.repeatKeyXOR.encrypt(plaintext, key)).to.eql(ciphertext);
    });
  });

  describe('Challenge 6 - break repeat key XOR', function() {
    it('should calculate the hamming distance between two strings', function() {
      
    });
  });
});
