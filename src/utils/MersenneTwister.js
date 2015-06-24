//
// MT19937 (Mersenne Twister) Pseudo Random Generator
//

// Initialise the generator from the seed
function MersenneTwister(seed) {
  // Constants
  this.N          = 624;
  this.M          = 397;
  this.UPPER_MASK = 0x80000000;
  this.LOWER_MASK = 0x7fffffff;

  // Generator Parameters
  this.index = 0;
  this.MT    = new Array(this.N);
  this.MT[0] = (seed >>> 0);
  
  // Initialise the generator from given seed
  for (var i = 1; i < this.N; i++) {
    var s  = this.MT[i-1] ^ (this.MT[i-1] >>> 30);

    this.MT[i] = 
      (((((s & 0xffff0000) >>> 16) * 0x6c078965) << 16) + 
        (s & 0x0000ffff) * 0x6c078965) + i;

    this.MT[i] >>>= 0;
  }
}

//  Extract a tempered pseudorandom number based on the index-th value,
//  calling generateNumbers() every 624 numbers
MersenneTwister.prototype.extractNumber = function() {
  var y;

  if ( this.index === 0 ) {
    this.generateNumbers();
  }
  
  y = this.MT[this.index];

  // Tempering
  y ^= (y >>> 11);
  y ^= (y << 7) & 0x9d2c5680;
  y ^= (y << 15) & 0xefc60000;
  y ^= (y >>> 18);

  this.index = (this.index + 1) % this.N;

  return y >>> 0;
};

// 'Un-Temper' function to retrieve an MT[i] element from an extractNumber() output
MersenneTwister.prototype.unTemper = function(mtOut) {
  var mti = mtOut;

  mti = unShiftRightXor(mti, 18);             // Inverts y ^= (y >>> 18);
  mti = unShiftLeftXor(mti, 15, 0xefc60000);  // Inverts y ^= (y << 15) & 0xefc60000;
  mti = unShiftLeftXor(mti, 7, 0x9d2c5680);   // Inverts y ^= (y << 7) & 0x9d2c5680;
  mti = unShiftRightXor(mti, 11);             // Inverts y ^= (y >>> 11);
  
  return mti << 0; 
};

// Generate an array of 624 untempered numbers
MersenneTwister.prototype.generateNumbers = function() {
  for (var i = 0; i < this.N; i++) {
    var y = (this.MT[i] & this.UPPER_MASK) + (this.MT[(i+1) % this.N] & this.LOWER_MASK);

    this.MT[i] = this.MT[(i + this.M) % this.N] ^ (y >>> 1);

    if (y % 2 !== 0) {
      this.MT[i] ^= 0x9908b0df;
    }
  }
};

// Functions to reverse left shift and xor operation
//
// 101101110101111001|11111001110010                     y
// 000000000000000000|10110111010111100111111001110010   y >>> 18
// 101101110101111001|01001110100101                     x = y ^ (y >>>18)
//
// -> first 18 bits of x[0:18] = y[0:18]
// -> last 14 bits of x[18:32] = y[0:14] ^ y[18:32]
// -> last 14 bits of y[18:32] = x[18:32] ^ y[0:14] 
//
// Can generalise the result to give unshift left/right with xor functions

// Function to reverse right shift and xor operation
function unShiftRightXor(value, shift) {
  var i      = 0;
  var result = 0;

  while (i * shift < 32) {
    
    // create a mask for this part
    var partMask = (-1 << (32 - shift)) >>> (shift * i);
    
    // obtain the part
    var part = value & partMask;
    
    // unapply the xor from the next part of the integer
    value ^= part >>> shift;
    
    // add the part to the result
    result |= part;

    i++;
  }

  return result >>> 0;
}

// Function to reverse left shift and xor operation with masking
function unShiftLeftXor(value, shift, mask) {
  var i      = 0;
  var result = 0;

  while (i * shift < 32) {

    // create a mask for this part
    var partMask = (-1 >>> (32 - shift)) << (shift * i);
    
    // obtain the part
    var part = value & partMask;

    // unapply the xor from the next part of the integer
    value ^= (part << shift) & mask;

    // add the part to the result
    result |= part;

    i++;
  }

  return result >>> 0;
}

exports.MersenneTwister = MersenneTwister;
exports.unShiftRightXor = unShiftRightXor;
exports.unShiftLeftXor  = unShiftLeftXor;
