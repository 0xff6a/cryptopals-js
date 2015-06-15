var _   = require('underscore');
var xor = require('./utils/xor.js');
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
    var el = numArr[i];

    modeMap[el] == null ? modeMap[el] = 1 : modeMap[el]++;

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

exports.xor       = xor;
exports.blocks    = blocks;
exports.mode      = mode;
exports.transpose = transpose;