var acme = require("acme");

acme.enableLocalUsage();

const ENABLE_SERVER = false;
if (ENABLE_SERVER) {
  var server = acme.createServer();
  server.listen(4000);
  console.log("Server listening on port 4000");
}

var authzURL = "http://localhost:4000/acme/new-authz";
var certURL = "http://localhost:4000/acme/new-cert";
acme.getMeACertificate(authzURL, certURL, "example.com", function(x) {
  console.log("Result of getMeACertificate:");
  console.log(x);
  if (ENABLE_SERVER) { server.close(); }
});
