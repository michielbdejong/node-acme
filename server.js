var acme = require("./lib/acme");

var server = acme.createServer();
server.listen(8888);
console.log("Server listening on port 8888");
