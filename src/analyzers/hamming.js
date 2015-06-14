var utils = require('../utils.js');
//
// Calculate hamming distance (number different bits) between two strings
//
// String (ascii), String (ascii) -> Number
//
function distance(s1, s2) {
  var buf1   = new Buffer(s1);
  var buf2   = new Buffer(s2);
  var xord   = utils.xor.bytes(buf1, buf2);
  var result = 0;

  for (var i = 0; i < xord.length; i++) {
    result += countPattern(xord[i].toString(2), '1');
  }

  return result; 
}

function countPattern(string, pattern) {
  return string.split(pattern).length - 1;
}

exports.distance = distance;