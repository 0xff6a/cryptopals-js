var fs         = require('fs');
var crypto     = require('crypto');
var expect     = require('expect.js');
var bignum     = require('bignum');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');


describe('Set 5', function() {
  describe('Challenge 33 - Implement Diffie-Hellman', function() {
    it('it should implement DH for small numbers', function() {
      var p  = bignum(37);
      var g  = bignum(5);
      
      // Generate the public/private key pairs for A and B
      var A  = encryption.diffieHellman.keyPair(p, g);
      var B  = encryption.diffieHellman.keyPair(p, g);

      // Calculate the shared key based on the others public key and own secret key
      var sA = encryption.diffieHellman.sharedKey(A.secretKey, B.publicKey, p); 
      var sB = encryption.diffieHellman.sharedKey(B.secretKey, A.publicKey, p);

      expect(sA).to.eql(sB);
    });

    it('should implement DH using NIST params by default', function() {
      // Generate the public/private key pairs for A and B
      var A  = encryption.diffieHellman.keyPair();
      var B  = encryption.diffieHellman.keyPair();

      // Calculate the shared key based on the others public key and own secret key
      var sA = encryption.diffieHellman.sharedKey(A.secretKey, B.publicKey); 
      var sB = encryption.diffieHellman.sharedKey(B.secretKey, A.publicKey);

      expect(sA).to.eql(sB);
    });
  });
});


