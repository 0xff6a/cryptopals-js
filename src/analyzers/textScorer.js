var BENCHMARK = 
{
  'a': 0.065336,
  'b': 0.011936,
  'c': 0.022256,
  'd': 0.034024,
  'e': 0.101616,
  'f': 0.017824,
  'g': 0.0161200,
  'h': 0.0487520,
  'i': 0.055728,
  'j': 0.001224,
  'k': 0.0061760,
  'l': 0.032200,
  'm': 0.019248,
  'n': 0.053992,
  'o': 0.060056,
  'p': 0.0154320,
  'q': 0.00076,
  'r': 0.047896,
  's': 0.050616,
  't': 0.072448,
  'u': 0.022064,
  'v': 0.0078240,
  'w': 0.01888,
  'x': 0.00120000,
  'y': 0.015792,
  'z': 0.0005920,
  ' ':  0.2
};
// 
// Calculate frequency each byte appears in a given string
//
// Buffer, Number -> Object
//
function frequency(buf, unit) {
  var chars = 
    buf
      .toString()
      .toLowerCase()
      .split('');

  return chars.reduce( function(result, char) {
    result[char] = (result[char] || 0) + unit;
    
    return result;
  }, {});
}
//
// Calculate frequency difference from benchmark
//
// Buffer -> Number
//
function calculate(buf) {
  var freq = relativeFreq(buf);

  return Object.keys(BENCHMARK).reduce( function(sumSq, char) {
    return Math.sqrt(
      Math.pow(
        sumSq + (BENCHMARK[char] - (freq[char] || 0)), 2
      )
    );
  }, 0);
}

exports.calculate    = calculate;
exports.absoluteFreq = absoluteFreq;

// ================================================================================================
// ================================================================================================

function relativeFreq(string) {
  return frequency(string, 1.0 / string.length);
}

function absoluteFreq(string) {
  return frequency(string, 1.0);
}
