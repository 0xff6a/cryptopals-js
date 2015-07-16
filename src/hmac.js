var utils = require('./utils.js');
var mac   = require('./mac.js');
var sleep = require('sleep');
var http  = require('http');
var Q     = require('q');
var _     = require('underscore');
//
// Block size for supported MACs : SHA1 & MD4
//
var BLOCK_SIZE = 64;
var DELAY      = 50000; //microseconds
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
    bufKey = pad0x00(bufKey, BLOCK_SIZE);
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
//
// Deliberately vulnerable bitwise comparison function
//
// Buffer, Buffer, Buffer -> Boolean
//
function insecureCompare(bufHmac, bufKey, bufM) {
  var validHmac = digest(mac.SHA1.digest, bufKey, bufM);

  for (var i = 0; i < validHmac.length; i++) {
    if (bufHmac[i] !== validHmac[i]) {
        return false;
    }
    
    sleep.usleep(DELAY);
  }

  return true;
}

exports.digest          = digest;
exports.insecureCompare = insecureCompare;

// ================================================================================================
// ================================================================================================


function pad0x00(buf, nSize) {
  bufTmp = new Buffer(nSize).fill(0x00);
  buf.copy(bufTmp);

  return bufTmp;
}