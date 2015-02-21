var assert = require('chai').assert;
var request = require('supertest');
var https = require('https');

var acme = require("../lib/acme");

var DEFAULT_KEY =
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  "MIIBOwIBAAJBAI0wy6Yxr8oK4IVCt7Ma+0rFDUJqA0xeDxrJ6xg8wVfaQydnNXLH\n" +
  "kcBeriMhC37DUygRigkEea5RSQkJcE521s8CAwEAAQJAcfjsu6iqNZdYLFpx/YOP\n" +
  "TIkKrgzzwqa+3KoYO8V3cVlNEZbzSFn0CAnznLPYzAY7yibDAVYWLVgJsdldOvtQ\n" +
  "UQIhAMH/JrN5znZigVnqxFrHJGbNjBTnir9CG1YYZsXWrIjJAiEAulEKSqpnuv9C\n" +
  "5btfRZ2E0oVal6+XzOajNagMqPJhRtcCIQCui7nwhcnj7mFf28Frw/3WmV5OeL33\n" +
  "s60Q28esfaijMQIgOjwCP3wrl+MZAb0i9htZ3IMZ4bdcdwrPkIHKEzRO+1kCIQC/\n" +
  "jUlCS7ny/4g4tY5dngWhQk3NUJasFzNuzTSx4ZGYWw==\n" +
  "-----END RSA PRIVATE KEY-----\n";

var DEFAULT_CERT =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBWDCCAQKgAwIBAgIBATANBgkqhkiG9w0BAQUFADAcMRowGAYDVQQDExFhbm9u\n" +
  "eW1vdXMuaW52YWxpZDAeFw0xNDA5MTMxOTU1MjRaFw0xNTA5MTMxOTU1MjRaMBwx\n" +
  "GjAYBgNVBAMTEWFub255bW91cy5pbnZhbGlkMFwwDQYJKoZIhvcNAQEBBQADSwAw\n" +
  "SAJBAI0wy6Yxr8oK4IVCt7Ma+0rFDUJqA0xeDxrJ6xg8wVfaQydnNXLHkcBeriMh\n" +
  "C37DUygRigkEea5RSQkJcE521s8CAwEAAaMvMC0wCQYDVR0TBAIwADALBgNVHQ8E\n" +
  "BAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEFBQADQQBpHaM7\n" +
  "mwRj19nt7sGb/trlxu5Ra0Ic4RGLI/VOZGWVV6hb2G559J2WdrdMS98U3L95lOoX\n" +
  "2fhD1yUCrh3aNtZP\n" +
  "-----END CERTIFICATE-----\n";

var domain, challenge, response, customServer = https.createServer({
  key: DEFAULT_KEY,
  cert: DEFAULT_CERT
}, function(req, resp) {
  console.log("---> Got request to ACME validation endpoint");
  console.log("~~~> url = " + req.url)
  console.log("~~~> my = /.well-known/acme-challenge/" + response.path);
  if ((req.headers.host == domain) &&
      (req.url == "/.well-known/acme-challenge/" + response.path)) {
    resp.writeHead(200, "OK", {
      "content-type": "text/plain",
      "connection": "close"
    });
    resp.write(challenge.token);
  } else {
    console.log('not found', req.url);
    resp.writeHead(404, "Not Found", {
      "connection": "close"
    });
  }
  resp.end();
}).listen(5001);//because we will call acme.enableLocalUsage() later

var server = acme.createServer();
server.listen(4000);

describe('challenge callback', function(){
  it('is called and cert is issued as expected', function(done){
    acme.enableLocalUsage();

    var keySize = 2048;
    var client = acme.createClient("https://localhost:4000/acme/new-authz", "https://localhost:4000/acme/new-cert", function(setDomain, setChallenge, setResponse) {
      console.log('challenge callback', setDomain, setChallenge, setResponse);
      domain = setDomain;
      challenge = setChallenge;
      response = setResponse;
      console.log('we are ready for the challenge');
    });
    var authorizedKeyPair = client.generateKeyPair(keySize);
    var subjectKeyPair = client.generateKeyPair(keySize);
    client.authorizeKeyPair(authorizedKeyPair, 'localhost', function(result) {
      // Result has a recovery key
      console.log('recovery key', result);
      client.issueCertificate(authorizedKeyPair, subjectKeyPair,
                              'localhost', function(result) {
        // Result has certificate
        var resultJSON = JSON.stringify(result);
        assert.notInclude(resultJSON, 'error');
        assert.include(resultJSON, 'certificate');
        server.close();
        customServer.close();
        done();
      });
    });
  });
});
