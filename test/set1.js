var expect = require('expect.js');

describe('Set 1', function() {
  describe('Challenge 1', function() {
    it('should convert hex to base64', function() {
      var hexString = 
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206" + 
      "120706f69736f6e6f7573206d757368726f6f6d";
      var b64String = 
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

      expect(hex.to_b64(hexString)).to.eq(b64String);
    });
  });
});
