Automated Certificate Management Environment (ACME)
===================================================

This module provides a proof of concept implementation of the ACME
protocol for certificate management.  Its main functions are:

* Validation of domain possession
* Certificate issuance
* Certificate revocation

The module provides both client and server implementations.  For
full details of the protocol, see the ACME protocol specification.


Quickstart
----------

```
> npm install node-acme
> node node-acme/demo.js
```


Client Side
-----------

An ACME client represents a certificate subject, such as a web
server.  For example, you might use ACME to acquire a certificate
when a new web server instance starts up.  This module provides
both a fine-grained client interface and a simple one-line call
to get a certificate.

```js
var acme = require("node-acme");
var acmeServer = "www.letsencrypt-demo.org";
var domain = "example.com";

// The easy way
acme.getMeACertificate(acmeServer, domain, function(result) {
  // Result has authorizedKeyPair, subjectKeyPair,
  //            recoveryKey, certificate
});

// The hard way
var keySize = 2048;
var authzURL = "https://" + acmeServer + "/acme/new-authz";
var certURL = "https://" + acmeServer + "/acme/new-cert";
var client = acme.createClient(authzURL, certURL);
var authorizedKeyPair = client.generateKeyPair(keySize);
var subjectKeyPair = client.generateKeyPair(keySize);
client.authorizeKeyPair(authorizedKeyPair, domain, function(result) {
  // Result has a recovery key
  
  client.issueCertificate(authorizedKeyPair, subjectKeyPair,
                          domain, function(result) {
    // Result has certificate
  });
});
```


Server side
-----------

An ACME server represents a CA in the management process.  Right
now, the server interface is fairly basic.  When started with no
parameters it will generate a new CA.  The state of the server can
can be retrieved using the `getState` method, and used to restart
the server in the same state later.

```js
var server = acme.createServer();
server.listen(8888);
// ... handle some client transactions ...
server.close();
```


TODO
----

* Enable HTTPS on client and server
* Implement additional domain validation mechansims
* Provide better server interface for managing the CA / server
* Support SANs and requests for certificates for multiple names
* Test that issued certs work in browsers (with the TA installed)
