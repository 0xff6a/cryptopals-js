//
// Implement the MT19937 (Mersenne Twister) Pseudo Random Generator
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
  this.MT[0] = seed;
  
  // Initialise the generator from given seed
  for (var i = 1; i < this.N; i++) {
    var s  = this.MT[i-1] ^ (this.MT[i-1] >>> 30);

    this.MT[i] = 
      (((((s & 0xffff0000) >>> 16) * 0x6c078965) << 16) + 
        (s & 0x0000ffff) * 0x6c078965) + i;

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

  return y;
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

exports.MersenneTwister = MersenneTwister;
