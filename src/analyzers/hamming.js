var utils = require('../utils.js');
//
// Calculate hamming distance (number different bits) between two strings
//
// Buffer, Buffer -> Number
//
function distance(buf1, buf2) {
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