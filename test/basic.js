var assert = require('chai').assert;
var request = require('supertest');

var acme = require("../lib/acme");

var server = acme.createServer();
server.listen(5000);

describe('verify demo works', function(){
  it('demo should return public and private keys', function(done){
    acme.enableLocalUsage();

    var url = "http://localhost:5000/";
    acme.getMeACertificate(url, "example.com", function(certJSON) {
      var cert = JSON.stringify(certJSON);
      assert.notInclude(cert, 'error');
      assert.include(cert, 'publicKey');
      assert.include(cert, 'privateKey');
      server.close();
      done();
    });
  });
});
