var utils = require('utils.js');
var mac   = require('mac.js');
//
// Block size for supported MACs : SHA1 & MD4
//
var BIT_M      = 8;
var BLOCK_SIZE = 512;
//
// Produces a keyed-hash message authentication code using a passed in hash function
// and secret key
//
// Function, Buffer, Buffer -> Buffer
//
function digest(fMac, bufKey, bufM) {

  // Keys longer than blocksize are shortened
  if (bufKey.length > BLOCK_SIZE) {
    bufKey = fMac(bufKey);
  } 

  // Keys shorter than blocksize are zero-padded
  if (bufKey.length < BLOCK_SIZE) {
    bufKey = //zero pad
  }

  // Create outer & inner padding
  oPad = new Buffer(BLOCK_SIZE).fill(0x5c);
  iPad = new Buffer(BLOCK_SIZE).fill(0x36);

  return fMac(Buffer.concat([
            utils.xor.bytes(oPad, bufKey),
            fMac(Buffer.concat([
              utils.xor.bytes(iPad, bufKey),
              bufM
            ]))
          ]));
} 

exports.digest = digest;