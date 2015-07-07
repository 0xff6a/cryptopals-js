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
//
// Server
//
var httpServer = (function() {
  module = {};

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
  module = {}

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
  module = {};

  module.test = function(req, res) {
    // HMAC logic
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.write('[+] Params: ');
    res.write('file:' + url.parse(req.url, true).query.file);
    res.write(' signature:' + url.parse(req.url, true).query.sign);
    res.end();
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

handle['/test'] = RequestHandler.test;
handle['404']   = RequestHandler.notFound;

httpServer.start(Router.route, handle);
