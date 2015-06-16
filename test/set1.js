var fs         = require('fs');
var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');
var analyzers  = require('../src/analyzers.js');
var oracles    = require('../src/oracles.js');

// newline character doesnt play well with built in decoder for b64
function bufferB64File(filepath) {
  return (new Buffer(fs.readFileSync(filepath, 'ascii'), 'base64'));
}

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

  describe('Challenge 3 - implement single char XOR', function() {
    it('should evaluate the frequency of characters in a string', function() {
      expect(analyzers.textScorer.absoluteFreq('abbcccddddeeeee')).to.eql({
        "a": 1, "b": 2, "c": 3, "d": 4, "e": 5
      });
    });

    it('should score strings based on character frequency vs average', function() {
      var english = analyzers.textScorer.calculate('hello my name is jeremy');
      var bad     = analyzers.textScorer.calculate('hello sjkbv');
      var worse   = analyzers.textScorer.calculate('sml£&0m,c');

      expect([bad, english, worse].sort()).to.eql([english, bad, worse]);
    });

    it('should decrypt single char XOR', function() {
      var bufCt = 
        new Buffer("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", 'hex');
      var plaintext = new Buffer("Cooking MC\'s like a pound of bacon");
      var decrypted = encryption.singleCharXOR.decryptNoKey(bufCt);

      expect(decrypted).to.eql(plaintext);
    });
  });

  describe('Challenge 4 - detect single char XOR', function() {
    it('should detect single char XOR from a set of sample strings', function() {
      var data = 
        fs
          .readFileSync('resources/4.txt')
          .toString()
          .split("\n")
          .map(function(ct) {
            return new Buffer(ct, 'hex');
          });

      var result = encryption.singleCharXOR.detect(data);
      var bufPt  = new Buffer("Now that the party is jumping\n");
      
      expect(result).to.eql(bufPt);
    });
  });

  describe('Challenge 5 - implement repeat key XOR', function() {
    it('should encrypt under repeat key XOR', function() {
      var bufKey = new Buffer('ICE');
      var bufPt  = 
        new Buffer(
          "Burning 'em, if you ain't quick and nimble\n" +
          "I go crazy when I hear a cymbal"
        );
      var bufCt = 
        new Buffer(
          "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
          "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", 'hex'
        );

      expect(encryption.repeatKeyXOR.encrypt(bufPt, bufKey)).to.eql(bufCt);
    });
  });

  describe('Challenge 6 - break repeat key XOR', function() {
    it('should calculate the hamming distance between two strings', function() {
      var buf1 = new Buffer('this is a test');
      var buf2 = new Buffer('wokka wokka!!!');

      expect(analyzers.hamming.distance(buf1, buf2)).to.eql(37);
    });

    it('should calculate the mode of an array', function() {
      var arr1 = [1, 2, 1, 1, 1, 2, 3, 5];
      var arr2 = [];

      expect(utils.mode(arr1)).to.eql(1);
      expect(utils.mode(arr2)).to.be(null);
    });

    it('should transpose an array of arrays', function() {
      var matrix = [[1, 2, 3], [4, 5, 6]];

      expect(utils.transpose(matrix)).to.eql([[1, 4], [2, 5], [3, 6]]);
    });

    it('should decrypt repeat key XOR without a key', function() {
      var data      = bufferB64File('resources/6.txt');
      var plaintext = 
        encryption
          .repeatKeyXOR
          .decryptNoKey(data)
          .toString()
          .slice(0, 150);

      expect(plaintext).to.eql(
        "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while" +
        " the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my" +
        " DJ Deshay cuttin\' all "
      );
    });
  });

  describe('Challenge 7 - AES in ECB mode', function() {
    var key    = new Buffer('YELLOW SUBMARINE');
    var data   = bufferB64File('resources/7.txt');
    var result = encryption.aesECB.decrypt(data, key);

    it('should decrypt an AES-ECB encrypted ciphertext given the key', function() {      
      var plaintext = 
        result
          .toString('ascii')
          .slice(0, 150);
      
      expect(plaintext).to.eql(
        "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while" +
        " the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my" +
        " DJ Deshay cuttin\' all "
      );
    });

    it('should encrypt a plaintext under AES-ECB', function() {
      var ciphertext = encryption.aesECB.encrypt(result, key);
      var plaintext  = encryption.aesECB.decrypt(ciphertext, key);

      expect(plaintext).to.eql(result);
    });
  });

  describe('Challenge 8 - detect AES in ECB mode', function() {
    it('should detect AES-ECB encryption', function() {
      var data = 
        fs
          .readFileSync('resources/8.txt')
          .toString()
          .split("\n");

      result = data.filter(function(ct) {
        var bufCt = new Buffer(ct, 'hex');

        return oracles.aesECB.detect(bufCt);
      });

      expect(result.length).to.eql(1);
      expect(data.indexOf(result.toString())).to.eql(132);
    });
  });
});
