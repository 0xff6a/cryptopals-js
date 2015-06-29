//
// PseudoCode
//
// Note 1: All variables are unsigned 32 bits and wrap modulo 232 when calculating, except
//         ml the message length which is 64 bits, and
//         hh the message digest which is 160 bits.
// Note 2: All constants in this pseudo code are in big endian.
//         Within each word, the most significant byte is stored in the leftmost byte position

var BIT_MULT = 8;


function digest(bufM) {
  // Initialize variables
  var h0 = 0x67452301;
  var h1 = 0xEFCDAB89;
  var h2 = 0x98BADCFE;
  var h3 = 0x10325476;
  var h4 = 0xC3D2E1F0;
  var mLen = bufM.length * BIT_MULT;
  var w = new Buffer(512 / BIT_MULT);

  // Pre-processing
  Buffer.concat([
    bufM,
    0x80,
     
  ])

}

// ml = message length in bits (always a multiple of the number of bits in a character).

// Pre-processing:
// append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
// append 0 ≤ k < 512 bits '0', thus the resulting message length (in bits)
//    is congruent to 448 (mod 512)
// append ml, in a 64-bit big-endian integer. So now the message length is a multiple of 512 bits.

// Process the message in successive 512-bit chunks:
// break message into 512-bit chunks
// for each chunk
//     break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15

//     Extend the sixteen 32-bit words into eighty 32-bit words:
//     for i from 16 to 79
//         w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1

//     Initialize hash value for this chunk:
//     a = h0
//     b = h1
//     c = h2
//     d = h3
//     e = h4

//     Main loop:[42]
//     for i from 0 to 79
//         if 0 ≤ i ≤ 19 then
//             f = (b and c) or ((not b) and d)
//             k = 0x5A827999
//         else if 20 ≤ i ≤ 39
//             f = b xor c xor d
//             k = 0x6ED9EBA1
//         else if 40 ≤ i ≤ 59
//             f = (b and c) or (b and d) or (c and d) 
//             k = 0x8F1BBCDC
//         else if 60 ≤ i ≤ 79
//             f = b xor c xor d
//             k = 0xCA62C1D6

//         temp = (a leftrotate 5) + f + e + k + w[i]
//         e = d
//         d = c
//         c = b leftrotate 30
//         b = a
//         a = temp

//     Add this chunk's hash to result so far:
//     h0 = h0 + a
//     h1 = h1 + b 
//     h2 = h2 + c
//     h3 = h3 + d
//     h4 = h4 + e

// Produce the final hash value (big-endian) as a 160 bit number:
// hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4

