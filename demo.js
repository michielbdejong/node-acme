var acme = require("acme");

acme.enableLocalUsage();

const ENABLE_SERVER = false;
if (ENABLE_SERVER) {
  var server = acme.createServer();
  server.listen(5000);
  console.log("Server listening on port 5000");
}

var url = "http://localhost:4000/acme";
acme.getMeACertificate(url, "example.com", function(x) {
  console.log("Result of getMeACertificate:");
  console.log(x);
  if (ENABLE_SERVER) { server.close(); }
});
