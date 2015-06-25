var encryption = require('../encryption.js');
var crypto     = require('crypto');
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
// Deliberately using key as IV to break!
//
// Function, String, Buffer -> Buffer
//
function encryptCommentString(fEncrypt, sUserData, bufKeyIv) {
  var bufPt;

  bufPt = new Buffer(
            'comment1=cooking%20MCs;userdata=' + 
            sanitize(sUserData) + 
            ';comment2=%20like%20a%20pound%20of%20bacon',
            'ascii'
          );

  return fEncrypt(bufPt, bufKeyIv, bufKeyIv);
}
//
// Checks whether an encrypted comment string has an admin token
//
// Deliberately using key as IV to break! 
//
// Function, Buffer, Buffer, Buffer -> Boolean
//
function isAdminComment(fDecrypt, bufCt, bufKeyIv) {
  var bufPt = fDecrypt(bufCt, bufKeyIv, bufKeyIv);
  var match = bufPt
                .toString()
                .match(/;admin=true;/);

  return !!match;
}
//
// Checks whether an encrypted comment string has only contains printable ascii
// If not returns an error code and the unencrypted string
//
// Function, Buffer, Buffer, Buffer -> Boolean
//
function parseComment(fDecrypt, bufCt, bufKeyIv) {
  var bufPt = fDecrypt(bufCt, bufKeyIv, bufKeyIv);

  if (!isValidQuery(bufPt)) {
    return { status: 500, input: bufPt};
  }

  return { status: 200 };
}
//
// Checks if input contains any non printable ASCII characters
//
// Buffer -> Boolean
//
function isValidQuery(bufPt) {
  for (var i = 0; i < bufPt.length; i++) {
    if (bufPt[i] > 127) {
      return false;
    } 
  }

  return true;
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
  result.ct = encryption.aesCBC.encrypt(bufPt, this.key, bufIv);

  return result;
};
//
// Checks for valid padding in an encrypted string
// 
// Object -> Boolean
//
CBCServer.prototype.isValidPadding = function(serverResult) {
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
exports.parseComment         = parseComment;
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

