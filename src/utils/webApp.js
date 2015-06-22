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
//
// Checks whether an encrypted comment string has an admin token
//
// Buffer, Buffer, Buffer -> Boolean
//
function isAdminComment(bufCt, bufKey, bufIv) {
  var bufPt = encryption.aesCBC.decrypt(bufCt, bufKey, bufIv);
  var match = bufPt
                .toString()
                .match(/;admin=true;/);

  return !!match;
}
//
// Creates a dummy server class for CBC padding attack
//
// Array(Buffer) -> cbcServer
//
function CBCServer(arrTargets) {
  this.key     = crypto.randomBytes(16);
  this.targets = arrTargets;
}
//
// Encrypts a random plaintext from a selection and returns ciphertext, iv
// 
// Null -> Object
//
CBCServer.prototype.encryptRandomSelection = function() {
  var index  = Math.round(Math.random() * this.targets.length);
  var bufPt  = this.targets[index];
  var bufIv  = crypto.randomBytes(16);
  var result = {};

  result.iv = bufIv;
  result.ct = encryption.aesCBC.encrypt(bufPt, this.key, bufIv)

  return result;
};
//
// Checks for valid padding in an encrypted string
// 
// Object -> Boolean
//
CBCServer.prototype.isValidPadding(serverResult) = function() {
  try {
    encryption.aesCBC.decrypt(serverResult.ct, this.key, serverResult.iv);
  } catch(err) {
    if (err.message.match(/padding invalid/)) {
      return false;
    }

    throw err;
  }

  return true;
};

exports.kvParse              = kvParse;
exports.profileFor           = profileFor;
exports.encryptedProfileFor  = encryptedProfileFor;
exports.decryptProfile       = decryptProfile;
exports.encryptCommentString = encryptCommentString;
exports.isAdminComment       = isAdminComment;
exports.CBCServer            = CBCServer;

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