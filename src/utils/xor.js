function hex(hex1, hex2) {
  var buf1 = new Buffer(hex1, 'hex');
  var buf2 = new Buffer(hex2, 'hex');
  var bufResult;

  bufResult = bitwiseXOR(buf1, buf2);

  return bufResult.toString('hex');
}

function bitwiseXOR(buf1, buf2) {
  if ( buf1.length !== buf2.length ) {
    throw new Error('Argument Error: uneqal size buffers');
  } else {
    var result = new Buffer(buf1.length);

    for (var i = 0; i < buf1.length; i++) {
      result[i] = buf1[i] ^ buf2[i];
    }

    return result;
  }
}

exports.hex = hex;