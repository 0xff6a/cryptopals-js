var utils = require('../utils.js');

var BIT_M      = 8;
var RET_SIZE   = 160;
var BLOCK_SIZE = 512;
var MASK       = 0xffffffff; // All arithmetic is modulo 2**32
//
// Generates a SHA-1 digest given a message buffer
//
// Due to limitations in JS this will process messages up to 2**32 - 1 
// size rather than 2**64 - 1
//
// Buffer -> Buffer
//
function digest(bufM) {
  
  // Initialize variables
  var h0 = 0x67452301;
  var h1 = 0xEFCDAB89;
  var h2 = 0x98BADCFE;
  var h3 = 0x10325476;
  var h4 = 0xC3D2E1F0;

  var hh = new Buffer(RET_SIZE / BIT_M);

  // Pre-processing (pad message to 512-bit blocks)
  bufM = padMD(bufM);

  // Process the message in successive 512-bit chunks:
  var chunksM = utils.blocks(bufM, BLOCK_SIZE / BIT_M);

  chunksM.forEach(function(chunk) {
    
    // Break chunk into sixteen 32-bit big-endian words
    var words = 
      utils
        .blocks(chunk, 32 / BIT_M)
        .map(function(bufW) {
          return bufW.readUInt32BE(0);
        });

    // Extend the sixteen 32-bit words into eighty 32-bit words:
    for (var i = 16; i < 80; i++) {
      words[i] = bitRotateL(
        (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]),
        1
      );
    }

    // Initialize hash value for this chunk:
    var a = h0;
    var b = h1;
    var c = h2;
    var d = h3;
    var e = h4;

    // Main loop calculating SHA function 80x
    for (i = 0; i < 80; i++) {
      if (i >= 0 && i < 20) {
        f = (b & c) | (~ b & d);
        k = 0x5A827999;
      } else if (i >= 20 && i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i >= 40 && i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else if (i >= 60 && i < 80) {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      temp = (bitRotateL(a, 5) + f + e + k + words[i]) & MASK;
      e    = d;
      d    = c;
      c    = bitRotateL(b, 30);
      b    = a;
      a    = temp;
    }

    // Add this chunk's hash to result so far:
    h0 = (h0 + a) & MASK;
    h1 = (h1 + b) & MASK; 
    h2 = (h2 + c) & MASK;
    h3 = (h3 + d) & MASK;
    h4 = (h4 + e) & MASK;
  });

  // Produce the final hash value (big-endian) as a 160 bit number:
  hh.writeUInt32BE(h0 >>> 0, 0);
  hh.writeUInt32BE(h1 >>> 0, 4);
  hh.writeUInt32BE(h2 >>> 0, 8);
  hh.writeUInt32BE(h3 >>> 0, 12);
  hh.writeUInt32BE(h4 >>> 0, 16);
 
  return hh;
}
//
// Authenticate a message using a secret key prefix MAX
//
// Buffer, Buffer -> Buffer
//
function authenticate(bufM, bufKey) {
  bufIn = Buffer.concat([bufKey, bufM]);

  return digest(bufIn);
}
//
// Verifies a supplied MAC for a message and key
//
// Buffer, Buffer, Buffer -> Boolean
//
function verify(bufMac, bufM, bufKey) {
  return bufMac.equals(authenticate(bufM, bufKey));
}
//
// Implements the SHA-1 padding scheme
//
// Buffer -> Buffer
//
function padMD(bufM) {
  var chunksM = utils.blocks(bufM, BLOCK_SIZE / BIT_M);
  var bufRaw  = chunksM.pop();
  var bufPad  = new Buffer(BLOCK_SIZE / BIT_M);
  
  var pLen    = bufPad.length;
  var mLen    = bufM.length;
  var bLen    = bufRaw.length;

  bufRaw.copy(bufPad);

  // Append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
  bufPad[bLen] = 0x80;

  // Append 0 ≤ k < 512 bits '0', thus the resulting message length (in bits)
  // is congruent to 448 (mod 512) 
  bufPad.fill(0x00, bLen + 1);

  // Append ml, in a 64-bit big-endian integer s.t message length is a multiple of 512 bits.
  // NO OP                                      //write the high order bits (shifted over)
  bufPad.writeUInt32BE(mLen * BIT_M, pLen - 4); //write the low order bits

  chunksM.push(bufPad);

  return Buffer.concat(chunksM);
}

exports.digest       = digest;
exports.padMD        = padMD;
exports.authenticate = authenticate;
exports.verify = verify;

// ================================================================================================
// ================================================================================================

function bitRotateL(number, shift) {
  return (number << shift) | (number >>> (32 - shift));
}

function mainSHA() {
  // Initialize hash value for this chunk:
  var a = h0;
  var b = h1;
  var c = h2;
  var d = h3;
  var e = h4;

  // Main loop calculating SHA function 80x
  for (i = 0; i < 80; i++) {
    if (i >= 0 && i < 20) {
      f = (b & c) | (~ b & d);
      k = 0x5A827999;
    } else if (i >= 20 && i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i >= 40 && i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else if (i >= 60 && i < 80) {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }

    temp = (bitRotateL(a, 5) + f + e + k + words[i]) & MASK;
    e    = d;
    d    = c;
    c    = bitRotateL(b, 30);
    b    = a;
    a    = temp;
  }
}
