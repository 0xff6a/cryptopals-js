var encryption = require('../encryption.js');
//
// Set of functions simulating a web application attacked in the challenges
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
//
// Creates an encrypted comment string
//
// String, Buffer -> Buffer
//
function encryptCommentString(sUserData, bufKey, bufIv) {
  var bufPt;

  bufPt = new Buffer(
            'comment1=cooking%20MCs;userdata=' + 
            sanitize(sUserData) + 
            ';comment2=%20like%20a%20pound%20of%20bacon',
            'ascii'
          );

  return encryption.aesCBC.encrypt(bufPt, bufKey, bufIv);
}

function isAdminComment(bufCt, bufKey, bufIv) {
  var bufPt = encryption.aesCBC.decrypt(bufCt, bufKey, bufIv);
  var match = bufPt
                .toString()
                .match(/;admin=true;/);

  return !!match;
}

exports.kvParse              = kvParse;
exports.profileFor           = profileFor;
exports.encryptedProfileFor  = encryptedProfileFor;
exports.decryptProfile       = decryptProfile;
exports.encryptCommentString = encryptCommentString;
exports.isAdminComment       = isAdminComment;

// ================================================================================================
// ================================================================================================

Object.prototype.pushPair = function(kv, delim) {
  var k = kv.split(delim)[0];
  var v = kv.split(delim)[1];

  this[k] = v;

  return this;
};

function sanitize(sUrl) {
  return sUrl
          .replace(/\\/g, "\\\\")
          .replace(/;/g, "\\;")
          .replace(/'/g, "\\'")
          .replace(/"/g, "\\\"");
}