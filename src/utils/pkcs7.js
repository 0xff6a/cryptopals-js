var utils = require('../utils.js');
//
// Add PKCS7 padding to a buffer. Note dummy block not added!
//
// Buffer, Number -> Buffer
//
function pad(buf, blockSize) {
  var blocks       = utils.blocks(buf, blockSize);
  var paddingBlock = blocks.pop();
  var padLen       = blockSize - buf.length;
  var bufPad       = new Buffer(padLen);

  bufPad.fill(String.fromCharCode(padLen));

  paddingBlock = 
    Buffer.concat([
      paddingBlock,
      bufPad
    ]);

  blocks.push(paddingBlock);

  return Buffer.concat(blocks);
}
//
// Strip PKCS7 padding from a buffer
//
// Buffer, Number -> Buffer
//
function strip(buf, blockSize) {
  var blocks       = utils.blocks(buf, blockSize);
  var paddingBlock = blocks.pop();
  var padLen;
  
  // Bad practice - deliberately implemented so we can attack it!
  if (!isValid(paddingBlock)) {
    throw new Error('PKCS7 padding invalid');
  }

  padLen       = paddingBlock[paddingBlock.length - 1];
  paddingBlock = paddingBlock.slice(0, -padLen);

  blocks.push(paddingBlock);

  return Buffer.concat(blocks);
}

exports.pad   = pad;
exports.strip = strip;

// ================================================================================================
// ================================================================================================
function isValid(bufPad) {
  var padLen   = bufPad[bufPad.length - 1];
  var validPad = buildPad(padLen);

  return bufPad.slice(-padLen).equals(validPad);
}

function buildPad(padLen) {
  var bufPad = new Buffer(padLen);

  bufPad.fill(String.fromCharCode(padLen));

  return bufPad;
}