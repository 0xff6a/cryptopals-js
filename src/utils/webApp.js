//
// Set of functions simulating a web application attacked in Challenge 13
//
//
// Parses a URL encoded 'cookie'
//
// String -> Object
//
function kvParse(sUrl) {
  var result = sUrl
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

exports.kvParse    = kvParse;
exports.profileFor = profileFor;

// ================================================================================================
// ================================================================================================

Object.prototype.pushPair = function(kv, delim) {
  var k = kv.split(delim)[0];
  var v = kv.split(delim)[1];

  this[k] = v;

  return this;
};