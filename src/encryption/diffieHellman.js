var bignum = require('bignum');
var crypto = require('crypto');
//
// NIST parameters
//
var gNIST = bignum('2'); 
var pNIST = bignum(
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
  p = p || pNIST;
  g = g || gNIST;

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
  p = p || pNIST;
  
  var rawS = bignum(publicKey.powm(nSecret, p));

  return createKey(rawS.toBuffer({ endian: 'big' }), 'sha256');
}

exports.keyPair   = keyPair;
exports.sharedKey = sharedKey;

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