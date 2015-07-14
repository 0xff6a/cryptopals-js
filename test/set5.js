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
      var alice = encryption.diffieHellman.keyPair(p, g);
      var bob   = encryption.diffieHellman.keyPair(p, g);

      // Calculate the shared key based on the others public key and own secret key
      var sA = encryption.diffieHellman.sharedKey(alice.secretKey, bob.publicKey, p); 
      var sB = encryption.diffieHellman.sharedKey(bob.secretKey, alice.publicKey, p);

      expect(sA).to.eql(sB);
    });

    it('should implement DH key exchange using NIST params by default', function() {
      var alice    = {};
      var bob      = {};
      
      expect(encryption.diffieHellman.keyExchange(alice, bob)).to.be(true); 
      expect(alice.secret).to.eql(bob.secret);
    });
  });

  describe('Challenge 34 - Implement DH MITM key fixing attack', function() {
    var p = encryption.diffieHellman.P_NIST;
    var g = encryption.diffieHellman.G_NIST;
    var alice;
    var bob;

    beforeEach(function() {
      // Create our alice and bob actors
      var sendEncrypted = function(oReceiver) {
        var bufIv = crypto.randomBytes(16);
        var bufCt = encryption.aesCBC.encrypt(
          new Buffer(this.message),
          this.secret.slice(0,16),
          bufIv
        );

        oReceiver.encrypted = Buffer.concat([bufIv, bufCt]);
      };

      var readEncrypted = function() {
        var bufCt = this.encrypted.slice(16);
        var bufIv = this.encrypted.slice(0, 16);

        return encryption.aesCBC.decrypt(
          bufCt,
          this.secret.slice(0,16),
          bufIv
        );
      };

      alice = { 
        message: 'This DH stuff is unhackeable!', 
        transmit: sendEncrypted, 
        receive: readEncrypted 
      };

      bob = { 
        message: 'You sure about that?', 
        transmit: sendEncrypted, 
        receive: readEncrypted 
      };
    });
      
    it('should implement a message exchange protocol using DH', function() {
      // Secure message exchange protocol
      //
      // A->B
      // Send "p", "g", "A"
      // B->A
      // Send "B"
      // A->B
      // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
      // B->A
      // Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
      // 
      encryption.diffieHellman.secureMessageExchange(alice, bob, p, g);

      expect(alice.receive().toString()).to.eql(bob.message);
      expect(bob.receive().toString()).to.eql(alice.message);
    });

    it('should implement a MITM attack against the protocol to retrieve the message', function() {
      //
      // MITM intercept replaces A,B with intercepted p
      // Secret key = A**a mod p = p**a mod p ... oh wait that's always 0!!
      //
      // A->M
      // Send "p", "g", "A"
      // M->B
      // Send "p", "g", "p"
      // B->M
      // Send "B"
      // M->A
      // Send "p"
      // A->M
      // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
      // M->B
      // Relay that to B
      // B->M
      // Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
      // M->A
      // Relay that to A
      //
      var aKeys = keyPair(p, g);
      var bKeys = keyPair(p, g);
      var eKeys = { publicKey: p, secret: 1 }; /* secret could be any value here */
      
      

    });
  });
});


