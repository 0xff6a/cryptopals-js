var utils  = require('../utils.js');
var bignum = require('bignum');

var BIT_M      = 8;
var RET_SIZE   = 160;
var BLOCK_SIZE = 512;
var MASK       = 0xffffffff; // All arithmetic is modulo 2**32
var H_SHA1     = [
  0x67452301,
  0xEFCDAB89,
  0x98BADCFE,
  0x10325476,
  0xC3D2E1F0
];
//
// Generates a SHA-1 digest given a message buffer. 
// Accepts fixed registers and prefix length as optional arguments
//
// Buffer[, Array(Number), Number] -> Buffer
//
function digest(bufM, hInitial, mLen) {
  
  // If no initial registers passed use the SHA-1 magic numbers
  if (hInitial === undefined) {
    hInitial = H_SHA1;
  }
  
  // Initialize variables
  var h0 = hInitial[0];
  var h1 = hInitial[1];
  var h2 = hInitial[2];
  var h3 = hInitial[3];
  var h4 = hInitial[4];

  var hh = new Buffer(RET_SIZE / BIT_M);

  // Pre-processing (pad message to 512-bit blocks)
  bufM = padMD(bufM, { mLen: mLen });

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

    // Main loop calculating SHA function 80x
    var registers = main([h0, h1, h2, h3, h4], words);

    // Add this chunk's hash to result so far:
    h0 = (h0 + registers[0]) & MASK;
    h1 = (h1 + registers[1]) & MASK; 
    h2 = (h2 + registers[2]) & MASK;
    h3 = (h3 + registers[3]) & MASK;
    h4 = (h4 + registers[4]) & MASK;
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
// MAC Authentication secret
//
var SECRET = new Buffer('YELLOW SUBMARINE');
//
// Authenticate a message using a secret key prefix MAX
//
// Buffer, Buffer -> Buffer
//
function authenticate(bufM) {
  bufIn = Buffer.concat([SECRET, bufM]);

  return digest(bufIn);
}
//
// Verifies a supplied MAC for a message and key
//
// Buffer, Buffer, Buffer -> Boolean
//
function verify(bufMac, bufM) {
  return bufMac.equals(authenticate(bufM));
}
//
// Implements the SHA-1 padding scheme, accepts an options object that defines:
//  -> fixed message length
//  -> fixed message prefix length
//
// Buffer, Number -> Buffer
//
function padMD(bufM, options) {
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
  // write the high order bits (shifted over)
  // NO OP  
  // write the low order bits                                    
  bufPad.writeUInt32BE((mLen + prefixLen) * BIT_M, bufPad.length - 4); 

  chunksM.push(bufPad);

  return Buffer.concat(chunksM);
}
//
// Forges a secret-prefix MAC given a message, original MAC and message to append
//
// Buffer, Buffer, Buffer -> Object
//
function forgeMAC(bufMac, bufOrig, bufAdd) {
  var hInitial = int32blocks(bufMac);

  for (var kLen = 1; kLen < 64; kLen++) { 
    var bufPad = padMD(bufOrig, { prefixLen: kLen });
    var bufNew = Buffer.concat([bufPad, bufAdd]);
    var mLen   = kLen + bufPad.length + bufAdd.length;
    var tmpMac = digest(bufAdd, hInitial, mLen);

    if (verify(tmpMac, bufNew)) {
      return { mac: tmpMac, msg: bufNew };
    }
  }
}

exports.digest       = digest;
exports.padMD        = padMD;
exports.authenticate = authenticate;
exports.verify       = verify;
exports.forgeMAC     = forgeMAC;

// ================================================================================================
// ================================================================================================

function bitRotateL(number, shift) {
  return (number << shift) | (number >>> (32 - shift)) & MASK;
}

function int32blocks(buf) {
  return utils
          .blocks(buf, 4)
          .map(function(b) {
            return b.readUInt32BE(0);
          });
}

function main(h, words) {
  // Initialize hash values for this chunk:
  var a = h[0];
  var b = h[1];
  var c = h[2];
  var d = h[3];
  var e = h[4];

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

  return [a, b, c, d, e];
}
