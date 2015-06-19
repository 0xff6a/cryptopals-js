var fs         = require('fs');
var crypto     = require('crypto');
var expect     = require('expect.js');
var utils      = require('../src/utils.js');
var encryption = require('../src/encryption.js');
var oracles    = require('../src/oracles.js');
var helpers    = require('./helpers.js');

describe('Set 3', function() {
  describe('Challenge 18  - Implement AES in CTR mode', function() {
    var bufCt  = 
      new Buffer('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==', 'base64');
    var bufKey    = new Buffer('YELLOW SUBMARINE');
    var bufNonce  = new Buffer(8).fill('\x00');
    var plaintext = encryption.aesCTR.decrypt(bufCt, bufKey, bufNonce);

    it('should increment a little endian ctr', function() {
      var bufCtr = new Buffer(8).fill('\x00', 'ascii');
      var once   = encryption.aesCTR.littleEndIncrement(bufCtr);
      var many   = new Buffer(8).fill('\x00', 'ascii');

      expect(once).to.eql(new Buffer('\x01\x00\x00\x00\x00\x00\x00\x00', 'ascii'));

      for (var i =0; i < 256; i++) {
        many = encryption.aesCTR.littleEndIncrement(bufCtr);
      }
      expect(many).to.eql(new Buffer('\xff\x02\x00\x00\x00\x00\x00\x00', 'ascii'));
    });

    it('should decrypt a AES::CTR encrypted ciphertext given nonce and key', function() {
      expect(plaintext).to.eql(new Buffer('Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby '));
    });

    it('should encrypt in AES::CTR mode', function() {
      expect(encryption.aesCTR.encrypt(plaintext, bufKey, bufNonce)).to.eql(bufCt);
    });
  });
  
  describe('Challenge 19 - Break fixed nonce CTR', function() {
    it('should decrypt a set of ciphertexts encrypted under a fixed nonce', function() { 
      var bufKey   = new Buffer('0f3bc4ed8e87a792a47d16657538d267', 'hex');
      var data     = helpers.ctr.encryptFromB64File('resources/19.txt', bufKey);

      var keyGuess = encryption.aesCTR.guessKeyStream(data);
      var pts      = helpers.ctr.decryptCtArray(data, keyGuess);

      // Not 100% decrypted but that comes in the next challenge
      expect(pts[1]).to.eql('roming.with vitid faces');
    });
  });

  describe('Challenge 20 - Break fixed nonce CTR statistically', function() {
    it('should decrypt fixed nonce CTR by modelling as repeat XOR', function() {
      var bufKey = new Buffer('7654b5c851a4c9dc869d96d684424ff4', 'hex');
      var data   = helpers.ctr.encryptFromB64File('resources/20.txt', bufKey);

      var plaintext = encryption.aesCTR.statisticalDecrypt(data).toString();
      
      expect(plaintext.slice(0, 150)).to.eql(
        ':\'m rated "R"...this is a warning, ya better void / ' +
        'P0uz I came back to attack others in spite- /' +
        ' Strike l1ut don\'t be afraid in the dark, in a park /'
      );
    });
  });

  describe('Challenge 21 - Implement the MT19937 RNG', function() {
    it('the RNG should produce the expected output', function() {
      var mt     = new utils.prg.MersenneTwister(1);
      var output = [];

      for (var i = 0; i < 200; i++) {
        output[i] = mt.extractNumber();
      }

      expect(output).to.eql([
        1791095845, 4282876139, 3093770124, 4005303368, 491263,     550290313, 1298508491,  4290846341,
        630311759,  1013994432, 396591248,  1703301249, 799981516,  1666063943, 1484172013, 2876537340,
        1704103302, 4018109721, 2314200242, 3634877716, 1800426750, 1345499493, 2942995346, 2252917204,
        878115723,  1904615676, 3771485674, 986026652,  117628829,  2295290254, 2879636018, 3925436996,
        1792310487, 1963679703, 2399554537, 1849836273, 602957303,  4033523166, 850839392,  3343156310,
        3439171725, 3075069929, 4158651785, 3447817223, 1346146623, 398576445,  2973502998, 2225448249,
        3764062721, 3715233664, 3842306364, 3561158865, 365262088,  3563119320, 167739021,  1172740723,
        729416111,  254447594,  3771593337, 2879896008, 422396446,  2547196999, 1808643459, 2884732358,
        4114104213, 1768615473, 2289927481, 848474627,  2971589572, 1243949848, 1355129329, 610401323,
        2948499020, 3364310042, 3584689972, 1771840848, 78547565,   146764659,  3221845289, 2680188370,
        4247126031, 2837408832, 3213347012, 1282027545, 1204497775, 1916133090, 3389928919, 954017671,
        443352346,  315096729,  1923688040, 2015364118, 3902387977, 413056707,  1261063143, 3879945342,
        1235985687, 513207677,  558468452,  2253996187, 83180453,   359158073,  2915576403, 3937889446,
        908935816,  3910346016, 1140514210, 1283895050, 2111290647, 2509932175, 229190383,  2430573655,
        2465816345, 2636844999, 630194419,  4108289372, 2531048010, 1120896190, 3005439278, 992203680,
        439523032,  2291143831, 1778356919, 4079953217, 2982425969, 2117674829, 1778886403, 2321861504,
        214548472,  3287733501, 2301657549, 194758406,  2850976308, 601149909,  2211431878, 3403347458,
        4057003596, 127995867,  2519234709, 3792995019, 3880081671, 2322667597, 590449352,  1924060235,
        598187340,  3831694379, 3467719188, 1621712414, 1708008996, 2312516455, 710190855,  2801602349,
        3983619012, 1551604281, 1493642992, 2452463100, 3224713426, 2739486816, 3118137613, 542518282,
        3793770775, 2964406140, 2678651729, 2782062471, 3225273209, 1520156824, 1498506954, 3278061020,
        1159331476, 1531292064, 3847801996, 3233201345, 1838637662, 3785334332, 4143956457, 50118808,
        2849459538, 2139362163, 2670162785, 316934274,  492830188,  3379930844, 4078025319, 275167074,
        1932357898, 1526046390, 2484164448, 4045158889, 1752934226, 1631242710, 1018023110, 3276716738,
        3879985479, 3313975271, 2463934640, 1294333494, 12327951,   3318889349, 2650617233, 656828586,
      ]);
    });
  });

  describe('Challenge 22 - Crack an MT19937 seed', function() {
    it ('should discover the seed from the first 32bit output of the RNG', function() {
      // Simulate the passage of time for the challenge
      //  -> sleep for t seconds (40-1000)
      //  -> seed RNG with current unix timestamp
      //  -> get first 32-bit RNG output
      //
      var unixTime = new Date().getTime();
      var minT     = 40;
      var maxT     = 1000;
      
      var t        = Math.floor(Math.random() * (maxT - minT + 1) + minT);
      var seed     = unixTime + t;
      var mt       = new utils.prg.MersenneTwister(seed);
      var mtOut    = mt.extractNumber();


      expect(oracles.mt19937.crackSeed(mtOut, unixTime + minT, unixTime + maxT)).to.eql(seed);
    });
  });

  describe('Challenge 23 - Clone an MT19937 RNG from its output', function() {
    it('should be able to reverse a right shift and XOR operation', function() {
      var y = Math.floor(Math.random() * (Math.pow(2, 32) - 1));
      var x = y ^ (y >>> 18);

      expect(utils.prg.unShiftRightXor(x, 18)).to.eql(y);
    });

    it('should be able to reverse a left shift and XOR operation', function() {
      var y = Math.floor(Math.random() * (Math.pow(2, 10) - 1));
      var x = y ^ (y << 15) & 0xefc60000;

      expect(utils.prg.unShiftLeftXor(x, 15, 0xefc60000)).to.eql(y);
    });

    it('should untemper a PRG output to retrieve the internal state variable', function() {
      var mt  = new utils.prg.MersenneTwister(1);
      var y   = mt.extractNumber();
      var mti = mt.unTemper(y);

      expect(mt.MT.indexOf(mti)).not.to.eql(-1);
    });

    it('should clone a generator from 624 outputs and predict the 625th output', function() {
      var seed   = Math.ceil(Math.random() * (Math.pow(2, 32) - 1));
      var target = new utils.prg.MersenneTwister(seed);
      var clone  = new utils.prg.MersenneTwister(1);
      var myMT   = [];

      for (var i = 0; i < target.N; i++) {
        var y = target.extractNumber();

        myMT.push(clone.unTemper(y));
      }

      clone.MT = myMT;

      expect(clone.MT).to.eql(target.MT);
      expect(clone.extractNumber()).to.eql(target.extractNumber());
    });
  });

  describe('Challenge 24 - create the MT19937 stream cipher and break it', function() {
    var bufKey   = crypto.randomBytes(2);
    var bufKnown = (new Buffer(14).fill('A'));
    var bufPt    = 
      Buffer.concat([
        crypto.randomBytes(helpers.randomInt(0, 64)),
        bufKnown
      ]);

    var bufCt = encryption.mt19937.encrypt(bufPt, bufKey);

    it('should encrypt/decrypt a plaintext using a MT19937 keystream', function() {
      var badKey = crypto.randomBytes(2);

      expect(encryption.mt19937.decrypt(bufCt, bufKey)).to.eql(bufPt);
      expect(encryption.mt19937.decrypt(bufCt, badKey)).not.to.eql(bufPt);
    });

    it('should reveal the ciphertext given a known plaintext segment', function() {
      expect(encryption.mt19937.decryptNoKey(bufCt, bufKnown)).to.eql(bufPt);
    });
  });
});
