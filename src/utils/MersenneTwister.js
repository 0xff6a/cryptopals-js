//
// Implement the MT19937 Pseudo Random Generator
//
function MersenneTwister(intSeed) {
  // Store the state of the generator
  this.SIZE = 624;
  this.MT   = new Array(SIZE);
  this.index = 0;

  // Initialise the generator from the seed
  this.MT[0] = intSeed;

  for (var i = 0; i < stateSize; i++) {
    // MT[i] := lowest 32 bits of(1812433253 * (MT[i-1] xor (right shift by 30 bits(MT[i-1]))) + i)
  }
}

MersenneTwister.prototype.extractNumber = function() {
  //  Extract a tempered pseudorandom number based on the index-th value,
  //  calling generate_numbers() every 624 numbers
  //  
  //  function extract_number() {
  //      if index == 0 {
  //          generate_numbers()
  //      }
   
  //      int y := MT[index]
  //      y := y xor (right shift by 11 bits(y))
  //      y := y xor (left shift by 7 bits(y) and (2636928640)) // 0x9d2c5680
  //      y := y xor (left shift by 15 bits(y) and (4022730752)) // 0xefc60000
  //      y := y xor (right shift by 18 bits(y))

  //      index := (index + 1) mod 624
  //      return y
  //  }
};

MersenneTwister.prototype.generateNumbers = function() {
  // Generate an array of 624 untempered numbers
  //
  //  function generate_numbers() {
  //      for i from 0 to 623 {
  //          int y := (MT[i] and 0x80000000)                       // bit 31 (32nd bit) of MT[i]
  //                         + (MT[(i+1) mod 624] and 0x7fffffff)   // bits 0-30 (first 31 bits) of MT[...]
  //          MT[i] := MT[(i + 397) mod 624] xor (right shift by 1 bit(y))
  //          if (y mod 2) != 0 { // y is odd
  //              MT[i] := MT[i] xor (2567483615) // 0x9908b0df
  //          }
  //      }
};



