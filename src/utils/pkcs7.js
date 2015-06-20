var utils = require('../utils.js');

var AES_BLOCK_SIZE = 16;
//
// Add PKCS7 padding to a buffer. Note dummy block not added!
//
// Buffer, Number -> Buffer
//
function pad(buf, blockSize) {
  // if (buf.length % blockSize === 0) {
  //   // Add a dummy padding block
  //   return Buffer.concat([buf, buildPad(blockSize)]);
  // }

  var blocks       = utils.blocks(buf, blockSize);
  var paddingBlock = blocks.pop();
  var padLen       = blockSize - paddingBlock.length;
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
// For AES
//
function padAES(buf) {
  return pad(buf, AES_BLOCK_SIZE);
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
  if (!isValid(paddingBlock, blockSize)) {
    throw new Error('PKCS7 padding invalid');
  }

  padLen       = paddingBlock[paddingBlock.length - 1];
  paddingBlock = paddingBlock.slice(0, -padLen);

  blocks.push(paddingBlock);

  return Buffer.concat(blocks);
}
//
// for AES
//
function stripAES(buf) {
  return strip(buf, AES_BLOCK_SIZE);
}

exports.pad      = pad;
exports.padAES   = padAES;
exports.strip    = strip;
exports.stripAES = stripAES;

// ================================================================================================
// ================================================================================================

function isValid(bufPad, blockSize) {
  var padLen = bufPad[bufPad.length - 1];
  var validPad;

  if (padLen > bufPad.length) {
    return false;
  }
   
  validPad = buildPad(padLen);

  return bufPad.slice(-padLen).equals(validPad);
}

function buildPad(padLen) {
  var bufPad = new Buffer(padLen);

  bufPad.fill(String.fromCharCode(padLen));

  return bufPad;
}