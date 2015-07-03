//
// PseudoCode
//
// Note 1: All variables are unsigned 32 bits and wrap modulo 232 when calculating, except
//         ml the message length which is 64 bits, and
//         hh the message digest which is 160 bits.
// Note 2: All constants in this pseudo code are in big endian.
//         Within each word, the most significant byte is stored in the leftmost byte position

var BIT_M = 8;

function digest(bufM) {
  // Initialize variables
  var h0 = 0x67452301;
  var h1 = 0xEFCDAB89;
  var h2 = 0x98BADCFE;
  var h3 = 0x10325476;
  var h4 = 0xC3D2E1F0;

  var blockSize = 512;
  var mLen      = bufM.length * BIT_M;
  var chunksM   = utils.block(bufM, blockSize / BIT_M);

  // Pre-processing (pad message to 512-bit blocks)
  chunksM = applyPadding(chunksM);

  // Process the message in successive 512-bit chunks:
  chunksM.forEach(function(chunk) {
    
    // Break chunk into sixteen 32-bit big-endian words
    var words = utils.block(chunk, 32 / BIT_M);

    // Extend the sixteen 32-bit words into eighty 32-bit words:
    for (var i = 16; i < 80; i++) {
      words[i] = (words[i-3] xor words[i-8] xor words[i-14] xor words[i-16]) leftrotate 1
    }

    // Initialize hash value for this chunk:
    var a = h0;
    var b = h1;
    var c = h2;
    var d = h3;
    var e = h4;

    // Main loop calculating SHA function
    for (i = 0; i < 80; i++) {
      if (i >= 0 && i < 20) {
        f = (b & c) | ((~ b) & d);
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

      temp = (a leftrotate 5) + f + e + k + words[i]
      e = d;
      d = c;
      c = b leftrotate 30
      b = a;
      a = temp;
    }

    // Add this chunk's hash to result so far:
    h0 = h0 + a;
    h1 = h1 + b; 
    h2 = h2 + c;
    h3 = h3 + d;
    h4 = h4 + e;
  });

  // Produce the final hash value (big-endian) as a 160 bit number:
  // hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
}

function applyPadding(chunksM) {
  var pad = chunksM.pop();

  // append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
  // append 0 ≤ k < 512 bits '0', thus the resulting message length (in bits)
  // is congruent to 448 (mod 512) append ml, in a 64-bit big-endian integer. 
  // So now the message length is a multiple of 512 bits.

  return Buffer.concat([
    chunksM,
    pad
  ]);
};