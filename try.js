var http  = require('http');
var async = require('async');
var _     = require('underscore');

//
// Spike for the HMAC timing discovery code
//
function timingDiscovery(fMac, sBaseUrl) {
  var validHmac = fMac(new Buffer(1));
  var sUrl      = sBaseUrl + validHmac.toString('hex');
  var index     = 0;

  function getResponseTime(n, done) {
    validHmac[index] = n;

    var initT = new Date();

    var req = http.get(sUrl, function(res) {
      deltaT = new Date() - initT;
      
      done(null, { 
        time: deltaT, byte: n 
      });
    });
    
    req.end();
  }

  function longestResponseTime(err, resTimes) {
    validHmac[index] = _.sortBy(resTimes, 'time').slice(-1).pop();
    index++
    updateGuess();
  }

  function updateGuess() {
    async.timesSeries(256, getResponseTime, longestResponseTime)
  }

  updateGuess();
}




