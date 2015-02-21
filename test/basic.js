var assert = require('chai').assert;
var request = require('supertest');

var acme = require("../lib/acme");

var server = acme.createServer();
server.listen(4000);

describe('verify demo works', function(){
  it('demo should return public and private keys', function(done){
    acme.enableLocalUsage();

    var acmeServer = "localhost:4000";
    acme.getMeACertificate(acmeServer, "example.com", function(certJSON) {
      var cert = JSON.stringify(certJSON);
      assert.notInclude(cert, 'error');
      assert.include(cert, 'publicKey');
      assert.include(cert, 'privateKey');
      server.close();
      done();
    });
  });
});
