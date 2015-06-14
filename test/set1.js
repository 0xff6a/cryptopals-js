var fs         = require('fs');
var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');
var analyzers  = require('../src/analyzers.js');

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
    it('Can evaluate the frequency of characters in a string', function() {
      expect(analyzers.textScorer.absoluteFreq('abbcccddddeeeee')).to.eql({
        "a": 1, "b": 2, "c": 3, "d": 4, "e": 5
      });
    });

    it('Can score strings based on character frequency vs average', function() {
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

  describe('Challenge 4 - SKIP FOR SPEED', function() {
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
});
