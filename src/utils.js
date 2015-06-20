var _      = require('underscore');
var xor    = require('./utils/xor.js');
var pkcs7  = require('./utils/pkcs7.js');
var prg    = require('./utils/MersenneTwister.js');
var o      = require('./utils/BlackBox.js');
var webApp = require('./utils/webApp.js');
//
// Buffer, Number -> Array(Buffer)
//
function blocks(buf, size) {
  var numBlocks = Math.ceil(buf.length / size);
  var result    = [];
  var offset    = 0;

  for (var i = 0; i < numBlocks; i++ ) {
    result.push(buf.slice(offset, size + offset));
    offset += size;
  }

  return result;
}
//
// Array(Number) -> Number
//
function mode(numArr) {
  if (numArr.length === 0) {
    return null;
  }

  var modeMap  = {};
  var maxCount = 1;
  var maxEl    = numArr[0];

  for(var i = 0; i < numArr.length; i++) {
    var el      = numArr[i];
    modeMap[el] = (modeMap[el] || 0) + 1; 

    if (modeMap[el] > maxCount)
    {
        maxEl    = el;
        maxCount = modeMap[el];
    }
  }

  return maxEl;
}
//
// Array(Array) -> Array(Array)
//
function transpose(matrix) {
  return _.zip.apply(_, matrix);
}

// Modules
exports.xor    = xor;
exports.pkcs7  = pkcs7;
exports.prg    = prg;
exports.o      = o;
exports.webApp = webApp;

// Functions
exports.blocks    = blocks;
exports.mode      = mode;
exports.transpose = transpose;
