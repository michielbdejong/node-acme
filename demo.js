var acme = require("./lib/acme");

// Uncomment this and change desiredIdentifier to a valid public DNS name if you
// would like to test against the live demo server.
//var acmeServer = "www.letsencrypt-demo.org";
var acmeServer = "localhost:4000";
var desiredIdentifier = "localhost";

// When running against a localhost ACME server, change ports accordingly and
// start up the server.
if (acmeServer.match(/localhost/)) {
  acme.enableLocalUsage();
  var server = acme.createServer();
  server.listen(4000);
  console.log("Server listening on port 4000");
}

var authzURL = "https://" + acmeServer + "/acme/new-authz";
var certURL = "https://" + acmeServer + "/acme/new-cert";
acme.getMeACertificate(authzURL, certURL, desiredIdentifier, function(x) {
  console.log("Result of getMeACertificate:");
  console.log(x);
  if (acmeServer.match(/localhost/)) {
    server.close();
  }
});
