var utils = require('../utils.js');
//
// Cracks the seed of an MT19937 PRG given its first output and a seed range
//
// Number, Number, Number -> Number
//
function crackSeed(prgOut, seedMin, seedMax) {
  for (var s = seedMin; s < seedMax + 1; s++) {
    var prg    = new utils.prg.MersenneTwister(s);
    var tmpOut = prg.extractNumber();

    if (tmpOut === prgOut) {
      return s;
    }
  }
}

exports.crackSeed = crackSeed;