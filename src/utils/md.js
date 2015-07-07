var bignum = require('bignum');
var utils  = require('../utils.js');

var BIT_M      = 8;
var BLOCK_SIZE = 512;
// Implements the MD padding scheme, accepts an options object that defines:
//  -> fixed message length
//  -> fixed message prefix length
//
// Buffer, Number -> Buffer
//
function pad(bufM, options) {
  var opt       = options || {};
  var prefixLen = opt.prefixLen || 0;
  var mLen      = opt.mLen || bufM.length;

  var chunksM   = utils.blocks(bufM, BLOCK_SIZE / BIT_M);
  var bufRaw    = chunksM.pop();
  var rLen      = bufRaw.length;
  var bufPad    = new Buffer((BLOCK_SIZE / BIT_M) - prefixLen);
  
  bufRaw.copy(bufPad);

  // Append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
  bufPad[rLen] = 0x80;

  // Append 0 ≤ k < 512 bits '0', thus the resulting message length (in bits)
  // is congruent to 448 (mod 512) 
  bufPad.fill(0x00, rLen + 1);

  // Append ml, in a 64-bit big-endian integer s.t message length is a multiple of 512 bits.
  bignum((mLen + prefixLen) * BIT_M)
    .toBuffer({ endian: 'big', size: 8 /* 8-byte / 64-bit */ })
    .copy(bufPad, bufPad.length - 8);

  chunksM.push(bufPad);

  return Buffer.concat(chunksM);
}

exports.pad = pad;