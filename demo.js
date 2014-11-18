var acme = require("./");

acme.enableLocalUsage();

var server = acme.createServer();
server.listen(5000);
console.log("Server listening on port 5000");

var url = "http://localhost:5000/";
acme.getMeACertificate(url, "example.com", function(x) {
  console.log("Result of getMeACertificate:");
  console.log(x);
  server.close();
});
