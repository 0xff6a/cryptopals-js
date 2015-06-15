var _      = require('underscore');
var aesECB = require('../encryption.js').aesECB;

function detect(buf) {
  var blocks = 
    aesECB
      .blocks(buf)
      .map( function(b) { 
        return b.toString('hex'); 
      });

  return (_.uniq(blocks).length !== blocks.length);
}

exports.detect = detect;
