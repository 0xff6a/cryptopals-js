// ================================================================================================
//
// Mini web application implementing HMAC to attack 
// (not using Express deliberately)
//
// Serves URL: http://localhost:9000/test?file=foo&signature=
// 46b4ec586117154dacd49d664e5d63fdc88efb51
//
// Verifies that signature on incoming request is valid for file
//
// ================================================================================================

var http = require('http');
var url  = require('url');
var hmac = require('./hmac.js');
var mac  = require('./mac.js'); 
//
// Secret Key
//
var KEY = new Buffer('SUPER SECRET');
//
// Server
//
var httpServer = (function() {
  var module = {};

  module.start = function(route, handle) {
    function onRequest(req, res) {
      var pathname = url.parse(req.url).pathname;

      route(handle, pathname, req, res);
    }

    http
      .createServer(onRequest)
      .listen(PORT);
  };

  return module;

} ());
//
// Routes
//
var Router = (function() {
  var module = {};

  module.route = function(handle, pathname, req, res) {
    if (typeof handle[pathname] === 'function') {
      handle[pathname] (req, res);
    } else {
      handle['404'] (req, res);
    }
  };

  return module;

} ());
// 
// Request Handling 
//
var RequestHandler = (function() {
  var module = {};

  function validHmac(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.write('[+] Valid Signature');
    res.end();
  }

  function badHmac(req, res) {
    res.writeHead(500, {'Content-Type': 'text/plain'});
    res.write('[-] Bad Signature!');
    res.end();
  }

  module.test = function(req, res) {
    var query     = url.parse(req.url, true).query;
    var signature = new Buffer(query.signature, 'hex');
    var data      = new Buffer(query.file);

    if (hmac.insecureCompare(signature, KEY, data)) {
      validHmac(req, res);
    } else {
      badHmac(req, res);
    }
  };

  module.notFound = function(req, res) {
    res.writeHead(404, {'Content-Type': 'text/plain'});
    res.write('[-] 404 NOT FOUND');
    res.end();
  };

  return module;

} ());
//
// Main
//
var PORT   = 9000;
var handle = {};

console.log('[+] Starting HMAC application on port ' + PORT);

handle['/test'] = RequestHandler.test;
handle['404']   = RequestHandler.notFound;

httpServer.start(Router.route, handle);
