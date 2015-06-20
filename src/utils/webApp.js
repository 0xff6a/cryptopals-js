var encryption = require('../encryption.js');
//
// Set of functions simulating a web application attacked in Challenge 13
//
//
// Parses a URL encoded profile 'cookie' string
//
// String -> Object
//
function kvParse(sProfile) {
  var result = sProfile
                .split('&')
                .reduce(function(res, kv) {
                  return res.pushPair(kv, '=');
                }, {});

  return result;
}
//
// Creates a profile string for user based on email
// 
// String -> String
//
function profileFor(sEmail) {
  var sProfile;

  sEmail   = sEmail.split('&')[0];
  sProfile = 'email=' + sEmail + '&uid=10&role=user';

  return sProfile;
}
//
// Creates an encrypted profile (using AES::ECB)
//
// String, Buffer -> Buffer
//
function encryptedProfileFor(sEmail, bufKey) {
  var bufProfile = new Buffer(profileFor(sEmail), 'ascii');

  return encryption.aesECB.encrypt(bufProfile, bufKey);
}
//
// Returns a decrypted profile hash 
//
// Buffer, Buffer -> Object
//
function decryptProfile(bufCt, bufKey) {
  var bufProfile = encryption.aesECB.decrypt(bufCt, bufKey);

  return kvParse(bufProfile.toString());
}

exports.kvParse             = kvParse;
exports.profileFor          = profileFor;
exports.encryptedProfileFor = encryptedProfileFor;
exports.decryptProfile      = decryptProfile;

// ================================================================================================
// ================================================================================================

Object.prototype.pushPair = function(kv, delim) {
  var k = kv.split(delim)[0];
  var v = kv.split(delim)[1];

  this[k] = v;

  return this;
};