var bignum = require('bignum');
var crypto = require('crypto');
//
// NIST parameters
//
var G_NIST = bignum('2'); 
var P_NIST = bignum(
  'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024' +
  'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd' +
  '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec' +
  '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f' +
  '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361' +
  'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552' +
  'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff' +
  'fffffffffffff', 16
);
//
// Creates a public key and secret. Defaults to NIST parameters 
// if none are supplied
//
// Bignum -> Bignum, Bignum
//
function keyPair(p, g) {
  p = p || P_NIST;
  g = g || G_NIST;

  var secret = genSecret(p);
  var public = g.powm(secret, p);

  return { secretKey: secret, publicKey: public };
}
//
// Generates a shared secret key given a secret and public key
//
// Bignum, Bignum -> Buffer
//
function sharedKey(nSecret, publicKey, p) {
  p = p || P_NIST;

  var rawS = bignum(publicKey.powm(nSecret, p));

  return createKey(rawS.toBuffer({ endian: 'big' }), 'sha1');
}
//
// Implements a DH key exchange between two objects and returns a Boolean result
//
// Object, Object -> Boolean
//
function keyExchange(oAlice, oBob, p, g) {
  var aKeys = keyPair(p, g);
  var bKeys = keyPair(p, g);

  oAlice.secret = sharedKey(aKeys.secretKey, bKeys.publicKey, p); 
  oBob.secret   = sharedKey(bKeys.secretKey, aKeys.publicKey, p);
  
  return oAlice.secret.equals(oBob.secret);
}
//
// Secure exchange of messages between two objects using DH key exchange
//
// Object, Object -> Null
//
function secureMessageExchange(oAlice, oBob, p, g) {
  keyExchange(oAlice, oBob, p, g);
  
  oAlice.transmit(oBob);
  oBob.transmit(oAlice);
}

exports.keyPair               = keyPair;
exports.sharedKey             = sharedKey;
exports.keyExchange           = keyExchange;
exports.secureMessageExchange = secureMessageExchange;
exports.G_NIST                = G_NIST;
exports.P_NIST                = P_NIST;

// ================================================================================================
// ================================================================================================
//
// Creates a secret given a modulo prime
//
// Bignum -> Bignum
//
function genSecret(nModulus) {
  return bignum(Math.floor(Math.random() * nModulus)).mod(nModulus);
}
//
// Creates a key buffer by hashing the shared DH secret
//
function createKey(nRaw, algorithm) {
  var hash = crypto.createHash(algorithm);
  hash.update(nRaw);

  return hash.digest();
}