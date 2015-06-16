var _ = require('underscore');

var BENCHMARK = 
{
  97:  0.065336,
  98:  0.011936,
  99:  0.022256,
  100: 0.034024,
  101: 0.101616,
  102: 0.017824,
  103: 0.0161200,
  104: 0.0487520,
  105: 0.055728,
  106: 0.001224,
  107: 0.0061760,
  108: 0.032200,
  109: 0.019248,
  110: 0.053992,
  111: 0.060056,
  112: 0.0154320,
  113: 0.00076,
  114: 0.047896,
  115: 0.050616,
  116: 0.072448,
  117: 0.022064,
  118: 0.0078240,
  119: 0.01888,
  120: 0.00120000,
  121: 0.015792,
  122: 0.0005920,
  32:  0.2
};
// 
// Calculate frequency each byte appears in a given string
//
// Buffer, Number -> Object
//
function absoluteFreq(buf) {
  return frequency(buf, 1.0);
}
//
// Calculate frequency difference from benchmark
//
// Buffer -> Number
//
function calculate(buf) {
  var freq = relativeFreq(buf);
  var sumSq;

  sumSq = Object.keys(BENCHMARK).reduce( function(accum, char) {
      return accum + Math.pow((BENCHMARK[char] - (freq[char] || 0)), 2);
  }, 0);

  return Math.sqrt(sumSq);
}
//
// Simplified text scorer based on whether or not it is a common ASCII character
//
// Buffer -> Number
//
function simple(buf) {
  var score = 0;

  for (var i = 0; i < buf.length; i++) {
    score += charScore(buf[i]);
  }

  return score;
}
//
// Number -> Number
//
function charScore(charCode) {
  var expectedRange = _.range(32, 123);
  var excludedRange = 
    _.range(0, 10)
    .concat(
      _.range(11, 32),
      [127],
      _.range(129, 153)
    )

  if (expectedRange.indexOf(charCode) !== -1) {
    return 1;
  }
    
  if (excludedRange.indexOf(charCode) !== -1) {
    return -99;
  }

  return 0;
}

exports.absoluteFreq = absoluteFreq;
exports.calculate    = calculate;
exports.simple       = simple;
exports.charScore    = charScore;

// ================================================================================================
// ================================================================================================

function relativeFreq(buf) {
  return frequency(buf, 1.0 / buf.length);
}

function frequency(buf, unit) {
  var result = {};
  
  for(var i = 0; i < buf.length; i++) {
    var charCode     = buf[i];
    result[charCode] = (result[charCode] || 0) + unit;
  }

  return result;
}


