var utils = require('../utils.js');

var W_SIZE = 4;
var K      = [ 0x00000000, 0x5a827999, 0x6ed9eba1];
var IV     = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

function digest(bufM) {

  // Initialize variables
  var a = IV[0];
  var b = IV[1];
  var c = IV[2];
  var d = IV[3];

  // Pre-processing (pad message to 512-bit blocks)
  bufM = utils.md.pad(bufM);

  // Split message into 32 bit words M = [Y1,Y2...YN-1]
  var M = utils.blocks(bufM, W_SIZE);
  var N = M.length - 1;

  for (var i = 0; i < (N / 16); i++) {
    // Copy block i into x
    x = M.slice(i, i + 16);
    
    // Copy x to w
    
    // Initialize q

    // Rounds 0, 1, 2
  }

  return a,b,c,d;
}

// ================================================================================================
// ================================================================================================

//
// F, G, H as defined in the MD4 specification
//
function F(a, b, c) {
  return (a & b) | (~a & c);
}

function G(a, b, c) {
  return (a & b) | (a & c) | (b & c);
}

function H(a, b, c) {
  return a ^ b ^ c;
}