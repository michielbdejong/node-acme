var async  = require("async");
var http   = require("http");
var https  = require("https");
var url    = require("url");
var tls    = require("tls");
var crypto = require("./crypto-util");
var util   = require("./acme-util");

/***** Constants *****/
const ENABLE_DEBUG          =  true;
const CA_KEY_SIZE           =  2048;
const CLIENT_KEY_SIZE       =  2048;
const DEFAULT_POLL_INTERVAL =  1000; // msec
const MIN_POLL_INTERVAL     =  2000; // msec
const MAX_POLL_INTERVAL     = 10000; // msec
const MAX_POLL              =  1000;
const VALIDATION_METHOD     = "simpleHttps";
const DVSNI_SUFFIX          = ".acme.invalid";

// By default, assume we're on heroku
// Local usage requires:
// * Different ports
// * Connecting to localhost in *Validation below
var ENABLE_LOCAL_USAGE = false;
var VALIDATION_CLIENT_PORT =  443;
var VALIDATION_SERVER_PORT =  443;

function enableLocalUsage() {
  ENABLE_LOCAL_USAGE = true;
  VALIDATION_CLIENT_PORT = 5001;
  VALIDATION_SERVER_PORT = 4000;
}


function DEBUG(message) {
  if (ENABLE_DEBUG) {
    console.log(message);
  }
}

/***** Default TLS certificate *****/

// The TLS server used for DVSNI requires a default key
// and certificate.  This is a valid key and cert, but it
// should never be accepted.

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

/***** Validation Methods *****/

function createChallenge(type) {
  switch (type) {
    case "simpleHttps":
      return SimpleHttpsChallenge();
    case "dvsni":
      return DvsniChallenge();
  }
  return null;
}

function createResponse(challenge) {
  switch (challenge.type) {
    case "simpleHttps":
      return SimpleHttpsResponse(challenge);
    case "dvsni":
      return DvsniResponse(challenge);
  }
  return null;
}

function createValidationServer(domain, challenge, response) {
  switch (challenge.type) {
    case "simpleHttps":
      return SimpleHttpsServer(domain, challenge, response);
    case "dvsni":
      return DvsniServer(domain, challenge, response);
  }
  return null;
}

function createValidationProcess(domain, type, challenge) {
  switch (type) {
    case "simpleHttps":
      return SimpleHttpsValidation(domain, challenge);
    case "dvsni":
      return DvsniValidation(domain, challenge);
  }
  return null;
}

function SimpleHttpsChallenge() {
  return {
    token: crypto.newToken()
  };
}

function SimpleHttpsResponse(challenge) {
  return {
    type: "simpleHttps",
    token: challenge.token,
    path: crypto.newToken()
  };
}

function SimpleHttpsServer(domain, challenge, response) {
  console.log("---> Creating SimpleHttpsServer");
  return https.createServer({
      key: DEFAULT_KEY,
      cert: DEFAULT_CERT
    }, function(req, resp) {
    console.log("---> Got request to ACME validation endpoint");
    console.log("~~~> url = " + req.url)
    console.log("~~~> my  = /.well-known/acme-challenge/" + response.path);
    if ((req.headers.host == domain) &&
        (req.url == "/.well-known/acme-challenge/" + response.path)) {
      resp.writeHead(200, "OK", {
        "content-type": "text/plain",
        "connection": "close"
      });
      resp.write(challenge.token);
    } else {
      resp.writeHead(404, "Not Found", {
         "connection": "close"
      });
    }
    resp.end();
  });
}

function SimpleHttpsValidation(domain, challenge) {
  var token = challenge.token;
  var path = challenge.path;

  var connectDomain = (ENABLE_LOCAL_USAGE)? "localhost" : domain;
  var options = {
    host: connectDomain,
    port: VALIDATION_CLIENT_PORT,
    path: "/.well-known/acme-challenge/" + path,
    headers: { "host": domain },
    // Since we are validating a host that does not yet have a valid
    // certificate, we don't insist that a valid certificate be presented when
    // we connect. It will most likely be a temporary self-signed one.
    rejectUnauthorized: false
  };

  return function(callback) {
    console.log("---> Performing SimpleHttps validation");
    var req = https.request(options, function(response) {
      var body = "";
      response.on("data", function(chunk) {
        body += chunk.toString();
      });
      response.on("end", function() {
        DEBUG("Got token=["+ body +"], expecting=["+ token +"]");
        callback(null, (body == token));
      });
    });
    req.on("error", function(error) {
      DEBUG("Error making validation HTTP request");
      DEBUG(error);
      callback(error, null);
    });
    req.end();
  };
}

function DvsniChallenge() {
  return {
    r: crypto.randomString(32),
    nonce: util.b64dec(crypto.randomString(16)).toString("hex")
  };
}

function DvsniResponse(challenge) {
  return {
    type: "dvsni",
    s: crypto.randomString(32)
  };
}

function DvsniServer(domain, challenge, response) {
  // Do all the crypto computations we need
  var nonceName = challenge.nonce + DVSNI_SUFFIX;
  var RS = Buffer.concat([util.b64dec(challenge.r), util.b64dec(response.s)]);
  var zName = crypto.sha256(RS).toString("hex") + DVSNI_SUFFIX;

  // Generate a key pair and certificate
  var keyPair = crypto.generateKeyPair(CLIENT_KEY_SIZE);
  var cert = crypto.generateDvsniCertificate(keyPair, nonceName, zName);
  var context = crypto.createContext(keyPair, cert);

  return tls.createServer({
    key: DEFAULT_KEY,
    cert: DEFAULT_CERT,
    SNICallback: function(serverName) {
      if (serverName == nonceName) {
        return context;
      }
    }
  });
}

function DvsniValidation(domain, challenge) {
  // Do all the crypto computations we need
  var nonceName = challenge.nonce + DVSNI_SUFFIX;
  var RS = Buffer.concat([util.b64dec(challenge.r), util.b64dec(challenge.s)]);
  var zName = crypto.sha256(RS).toString("hex") + DVSNI_SUFFIX;

  var connectDomain = (ENABLE_LOCAL_USAGE) ? "localhost" : domain;
  var options = {
    host: connectDomain,
    servername: nonceName,
    port: VALIDATION_CLIENT_PORT,
    rejectUnauthorized: false
  };

  return function(callback) {
    var stream = tls.connect(options, function() {
      // Grab the cert's SAN extension and close the stream
      var san = stream.getPeerCertificate().subjectaltname;
      stream.end();
      if (!san) {
        callback(null, false);
        return;
      }

      // node.js returns the SAN in OpenSSL's text format
      var searchName = "DNS:" + zName;
      callback(null, san.indexOf(searchName) > -1);
    });
  };
}

/***** Server helper methods *****/

function forbiddenIdentifier(id) {
  // TODO Flesh this out.  Only rough checks for now

  // If it contains characters not allowed in a domain name ...
  if (id.match(/[^a-zA-Z0-9.-]/)) {
    return true;
  }

  // If it is entirely numeric ...
  if (!id.match(/[^0-9.]/)) {
    return true;
  }

  return false;
}

// Verify an incoming POST body:
// * Decode JWS
// * Verify JWS
// * Decode JWS payload
//
// Return null on error
function verifyPost(body) {
  if (body.length == 0) {
    return null;
  }

  var jws = null;
  try {
    jws = JSON.parse(body);

    if (!crypto.verifySignature(jws)) {
      return null;
    }

    var payload = util.b64dec(jws.payload).toString();
    var parsedPayload = JSON.parse(payload);
    ret = {
      key: jws.header.jwk,
      body: parsedPayload
    };
    return ret;
  } catch (e) {
    return null;
  }
}

function keysAreEqual(jwk1, jwk2) {
  return (jwk1.kty == jwk2.kty) &&
    (((jwk1.kty == "RSA") && (jwk1.n == jwk2.n) && (jwk1.n == jwk2.n)) ||
     ((jwk1.kty == "EC") && (jwk1.crv == jwk2.crv) &&
                            (jwk1.x == jwk2.x) && (jwk1.y == jwk2.y)));
}

function mergeClientAuthz(dst, src) {
  for (key in dst.challenges) {
    if (!(key in src.challenges)) {
      continue;
    }

    switch (key) {
      case "simpleHttps":
        dst.challenges[key].path = src.challenges[key].path;
        break;
      case "dvsni":
        dst.challenges[key].s = src.challenges[key].s;
        break;
    }
  }

  if (src.contact) {
    dst.contact = src.contact
  }

  return dst;
}

function completeChallenge(type, challenge) {
  switch (type) {
    case "simpleHttps":
      return (challenge.token && challenge.path);
    case "dvsni":
      return (challenge.r && challenge.s && challenge.nonce);
    default:
      return false;
  }
}


/**
 *  createServer(state?)
 *
 *  Creates an ACME server object that performs ACME certificate management
 *  functions when requested by clients.
 *
 *  For persistence, the server will provide its full state on request.  If
 *  this state is provided in the createServer() call, this method will
 *  create a server with that state.  Otherwise, new state will be generated,
 *  including a new root CA key pair.  If partial state is provided, it will
 *  be used, and missing fields will be set to default values.
 *
 *  State variables and their defaults are listed in the code below.
 *
 *  Methods:
 *    * getState() => { [Full state of the server as a JS object] }
 *    * listen(port) => void
 *    * close() => void
 *
 **/
function createServer(state_in) {
  // State variables
  var log = []; // of HTTP messages
  var state = {
    distinguishedName: [{ name: "organizationName", "value": "ACME" }],
    baseURL: "https://localhost:4000/acme/",
    authzBase: "https://localhost:4000/acme/authz/",
    certBase:  "https://localhost:4000/acme/cert/",
    keyPair: null,
    certificate: null,
    authorizedKeys: {},      // Domain -> [ Keys ]
    certificates: {},        // Serial -> Certificate
    authorizations: {},      // Token  -> Authorization
    revocationStatus: {},    // Certificate -> boolean
  }

  // If state is provided, use it
  if (state_in) {
    for (var key in state_in) {
      state[key] = state_in[key];
    }
  }

  // Generate a key pair if we need to
  if (!state.keyPair) {
    state.keyPair = crypto.generateKeyPair(CA_KEY_SIZE);
  }

  function emptyResponse(code) {
    return {code: code, headers: {}, body: ""};
  }

  // ACME message handlers
  function handleNewAuthz(method, headers, body) {
    if (method != "POST") {
      return emptyResponse(405);
    }

    var ver = verifyPost(body);
    if (!ver) {
      return emptyResponse(400);
    }
    // TODO further validation on request object

    // Check that we're willing to issue for this identifier
    if (forbiddenIdentifier(ver.body.identifier.value)) {
      return emptyResponse(403);
    }

    // Make a new authorization and store it
    var authzID = crypto.newToken();
    var authz = {
      identifier: ver.body.identifier,
      key: ver.key,
      status: "pending",
      challenges: {
        "simpleHttps": SimpleHttpsChallenge(),
        "dvsni": DvsniChallenge()
      }
    };
    state.authorizations[authzID] = authz;

    return {
      code: 201,
      headers: {
        location: state.authzBase + authzID
      },
      body: JSON.stringify(authz)
    };
  }

  function handleAuthz(method, path, headers, body) {
    var id = path.replace(/^.*\//, "");
    if (!state.authorizations[id]) {
      return emptyResponse(404);
    }
    var authz = state.authorizations[id];
    var identifier = authz.identifier.value;

    switch (method) {
      case "GET":
        return {
          code: authz.status === "valid" ? 200 : 403,
          headers: {},
          body: JSON.stringify(authz)
        }

      case "POST":
        var ver = verifyPost(body);
        if (!ver) {
          return emptyResponse(400);
        }

        // Check that this is the same key as before
        if (!keysAreEqual(ver.key, ver.body.key)) {
          return emptyResponse(403);
        }

        authz = mergeClientAuthz(authz, ver.body);
        state.authorizations[id] = authz;

        // Queue up validation processes
        var validationProcesses = [];
        for (key in authz.challenges) {
          if (completeChallenge(key, authz.challenges[key])) {
            console.log("===> Validating " + key);
            validationProcesses.push(createValidationProcess(
                                     identifier, key, authz.challenges[key]));
          }
        }
        if (validationProcesses.length > 0) {
          console.log("===> Starting validation on "+ JSON.stringify(validationProcesses));
          async.parallel(validationProcesses,
            function(err, results) {
              // Validation succeeds if any challenge succeeds
              validationResult = results.reduce(function(x,y) { return x || y; });

              // If we were unable to validate, fail
              if (!validationResult) {
                authz.status = "invalid";
                state.authorizations[id] = authz;
                return;
              }

              // Otherwise, mark the authz valid and remember the authorized key
              authz.status = "valid";
              state.authorizations[id] = authz;
              var fp = util.keyFingerprint(authz.key);
              if (!state.authorizedKeys[fp]) {
                state.authorizedKeys[fp] = {};
              }
              state.authorizedKeys[fp][identifier] = true;
            })
        } else {
          console.log("===> No complete challenges found ");
        }

        return {
          code: 202,
          headers: { "retry-after": 5 },
          body: JSON.stringify(authz)
        };

      default:
        return emptyResponse(405);
    }
  }

  function handleNewCert(method, headers, body) {
    if (method != "POST") {
      return emptyResponse(405);
    }

    var ver = verifyPost(body);
    if (!ver) {
      return emptyResponse(400);
    }
    // TODO further validation on request object

    // Validate CSR and authorization for domain
    var identifier = crypto.verifiedCommonName(ver.body.csr);
    var fp = util.keyFingerprint(ver.key);
    if (!state.authorizedKeys[fp] || !state.authorizedKeys[fp][identifier]) {
      return emptyResponse(403);
    }

    do {
      serialNumber = crypto.randomSerialNumber();
    } while (serialNumber in state.certificates);
    var certificate = crypto.generateCertificate({
      distinguishedName: state.distinguishedName,
      keyPair: state.keyPair
    }, serialNumber, ver.body.csr);

    // Store state about this certificate
    state.certificates[serialNumber] = certificate;
    state.revocationStatus[serialNumber] = false;

    return {
      code: 201,
      headers: {
        location: state.certBase + serialNumber
      },
      body: certificate
    };
  }

  function handleCert(method, path, headers, body) {
    var id = path.replace(/^.*\//, "");
    if (!state.certificates[id]) {
      return emptyResponse(404);
    }

    switch (method) {
      case "GET":
        // TODO content negotiation
        // TODO Link header
        return {
          code: 200,
          headers: {},
          body: state.certificates[id]
        }

      case "POST":
        var ver = verifyPost(body);
        if (!ver || !ver.body.revoke) {
          return emptyResponse(400);
        }
        // TODO verify that signign key is authorized

        state.revocationStatus[id] = true;
        return emptyResponse(200);

      default:
        return emptyResponse(405);
    }
  }

  // The main dispatch method and actual HTTP server
  function handleAcmeRequest(request, response){
    var body = "";
    var path = url.parse(request.url).pathname;

    // Dispatch based on path (hard-coded)
    function dispatch() {
      var result = { code: 404 };
      if (path == "/acme/new-authz") {
        result = handleNewAuthz(request.method, request.headers, body);
      } else if (path == "/acme/new-cert") {
        result = handleNewCert(request.method, request.headers, body);
      } else if (path.match("^/acme/authz/")) {
        result = handleAuthz(request.method, path, request.headers, body);
      } else if (path.match("^/acme/cert/")) {
        result = handleCert(request.method, path, request.headers, body);
      }

      response.writeHead(result.code, result.headers);
      if (result.body) {
        response.write(result.body);
      }
      response.end();
    }

    // Read the body if POST
    if (request.method == "POST") {
      request.on("data", function(chunk) {
        // All request bodies should be text
        body += chunk;
      });
      request.on("end", function() { dispatch(); })
    } else if (request.method == "GET") {
      dispatch();
    } else {
      response.writeHead(405);
      response.end();
      return;
    }
  }

  var server = https.createServer({
      key: DEFAULT_KEY,
      cert: DEFAULT_CERT
    }, handleAcmeRequest);

  return {
    getLog: function() {
      return log;
    },

    getState: function() {
      return state;
    },

    setPrivateKey: function(pem) {
      state.keyPair = crypto.importPemPrivateKey(pem);
    },

    setCertificate: function(pem) {
      state.certificate = crypto.importPemCertificate(pem);
      state.distinguishedName = state.certificate.issuer.attributes;
    },

    listen: function(port) {
      return server.listen(port);
    },

    close: function() {
      return server.close();
    },
  }
}


// Slightly simplified HTTP request method.
// * If body != null sends a POST with the body (assumed JSON)
// * Callback called with:
//    * Response code
//    * Header dictionary
//    * Body
function sendHttpRequest(serverURL, body, callback) {
  var opts = url.parse(serverURL);
  if (body) {
    opts.method = "POST";
    opts.headers = {
      "Content-Type": "application/json"
    }
  }

  // If the ACME server is local, don't bother authenticating the cert.
  if (serverURL.match(/^https:\/\/localhost:4000\//)) {
    opts.rejectUnauthorized = false
  }

  function handleResponse(res) {
    var buffer = new Buffer(0);

    res.on('data', function(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
    });
    res.on('end', function() {
      DEBUG("<~~~ HTTP RESPONSE");
      DEBUG("       Code: " + res.statusCode);
      DEBUG("       Header: " + JSON.stringify(res.headers));
      DEBUG("       Body: " + buffer);
      callback(res.statusCode, res.headers, buffer);
    });
  }

  DEBUG("~~~> HTTP REQUEST");
  DEBUG("       Method: " + opts.method || "GET");
  DEBUG("       URL: " + serverURL);
  DEBUG("       Body: " + body);
  var req = https.request(opts, handleResponse);
  if (body) {
    req.write(body);
  }
  req.end();
}

function jsonOrNull(buffer) {
  try {
    return JSON.parse(buffer.toString());
  } catch (e) {
    return null;
  }
}

/**
 *  createClient(authzURL, certURL[, challengeCallback])
 *
 *  Creates an ACME client object that implements ACME certificate
 *  management functions.  The only inputs are the URLs for the ACME server,
 *  and an optional challenge callback.
 *
 *  Methods:
 *    * generateKeyPair(bits) => { publicKey: ..., privateKey: ...}
 *    * authorizeKeyPair(keyPair, domain) => { url: ..., authorization: ... }
 *    * issueCertificate(authorizedKeyPair, subjectKeyPair, domain)
 *          => { certificate: ...}
 *    * revokeCertificate(authorizedKeyPair, cert) => boolean
 *
 *  Notes:
 *    * All methods take a callback as final argument
 *    * Callback will be called with an object encoding the result
 *      if (result.error) { something bad happened }
 *      else { format of result is method-specific }
 **/
function createClient(authzURL, certURL, challengeCallback) {
  return {
    newAuthzURL: authzURL,
    newCertURL:  certURL,
    authorizations: {}, // map[URL]Authorization
    certificates: {}, // map[URL]Certificate

    generateKeyPair: crypto.generateKeyPair,

    authorizeKeyPair: function(keyPair, domain, callback) {
      var tempServer = null;
      var authzURL = "";
      var client = this; // for reference in closures

      function handleChallenge(code, header, body) {
        if ((code != 201) || !("location" in header) || !body) {
          callback({ error: "Unacceptable challenge response" })
          DEBUG(code); DEBUG(header); DEBUG(body);
          return;
        }
        authzURL = header.location;

        var authz = jsonOrNull(body);
        if (!authz) {
          callback({ error: "New authz wasn't JSON" })
          return;
        }

        if (("status" in authz) && (authz.status != "pending")) {
          callback({ error: "New authz not in pending state" })
          return;
        }

        if (!("challenges" in authz)) {
          callback({ error: "New authz provided no challenges" })
          return;
        }

        // Respond to simpleHttps, or failing that, DVSNI
        if ("simpleHttps" in authz.challenges) {
          var challenge = authz.challenges.simpleHttps;
          var response = SimpleHttpsResponse(challenge);
          authz.challenges.simpleHttps.path = response.path;
          if (challengeCallback) {
            challengeCallback(domain, challenge, response, 'simpleHttps');
          } else {
            tempServer = SimpleHttpsServer(domain, challenge, response);
          }
        } else if ("dvsni" in authz.challenges) {
          var challenge = authz.challenges.dvsni
          var response = DvsniResponse(challenge);
          authz.challenges.dvsni.s = response.s;
          if (challengeCallback) {
            challengeCallback(domain, challenge, response, 'dvsni');
          } else {
            tempServer = DvsniServer(domain, challenge, response);
          }
        } else {
          callback({ error: "No challenges provided" })
          return;
        }

        // Start the validation server
        if (tempServer) {
          tempServer.unref();
          try {
            tempServer.once('error', function(err) {
              console.log('Error setting up temp server:', err);
              if (err.code === 'EADDRINUSE') {
                console.log('Could not bind to port', VALIDATION_CLIENT_PORT,
                  'kill other processes using it (sudo fuser -kivn tcp',
                  VALIDATION_CLIENT_PORT, ')');
              } else if (err.code === 'EACCES') {
                if (VALIDATION_CLIENT_PORT === 443 && process.getuid() != 0) {
                  console.log('Could not bind to port', VALIDATION_CLIENT_PORT,
                    '. Run this process as root.');
                }
              }
              process.exit(1);
            });
            tempServer.listen(VALIDATION_CLIENT_PORT);
          } catch (e) {
            // Most commonly, couldn't bind to the port
            return {
              error: "Unable to bind temp server to a port"
            }
          }
        }

        // Send the updated authz object to the authz URL
        var request = JSON.stringify(authz);
        var signedRequest = crypto.generateSignature(keyPair, new Buffer(request));
        var jsonSignedRequest = JSON.stringify(signedRequest)
        sendHttpRequest(authzURL, jsonSignedRequest, waitForFinalAuthorization);
      }

      var polls = 0;
      function waitForFinalAuthorization(code, header, body) {
        if (code == 200) {
          var authz = JSON.parse(body);
          if (authz.status === "valid") {
            handleAuthorization(code, header, body);
            return;
          }
        } else if (code >= 300) {
          callback({ error: "Got a redirect or final error code "+code });
          return;
        }

        polls += 1;
        if (polls > MAX_POLL) {
          callback({ error: "Max number of polls exceeded" });
          return;
        }

        var interval = DEFAULT_POLL_INTERVAL;
        if (("retry-after" in header) &&
            (!header["retry-after"].match(/[^0-9]/))) {

        }

        var msec = DEFAULT_POLL_INTERVAL;
        if (("retry-after" in header) &&
            (!header["retry-after"].match(/[^0-9]/))) {
          msec = parseInt(header["retry-after"]) * 1000;
          msec = (msec > MAX_POLL_INTERVAL)? MAX_POLL_INTERVAL : msec;
          msec = (msec < MIN_POLL_INTERVAL)? MIN_POLL_INTERVAL : msec;
        }

        setTimeout(function() {
          sendHttpRequest(authzURL, null, waitForFinalAuthorization);
        }, msec);
      }

      function handleAuthorization(code, header, body) {
        // Shut down validation server regardless of response
        if (tempServer) {
          tempServer.close();
        }

        var authz = jsonOrNull(body);
        if (!authz) {
          callback({ error: "Final authz wasn't JSON" });
          DEBUG("Final authz wasn't JSON");
          DEBUG(code);
          DEBUG(header);
          DEBUG(body);
          return;
        }

        client.authorizations[authzURL] = authz;
        callback({
          url: authzURL,
          authorization: authz
        });
      }

      var request = JSON.stringify({
        identifier: {
          type: "dns",
          value: domain
        }
      });
      var signedRequest = crypto.generateSignature(keyPair, new Buffer(request));
      var jsonSignedRequest = JSON.stringify(signedRequest)
      sendHttpRequest(client.newAuthzURL, jsonSignedRequest, handleChallenge);
    },

    issueCertificate: function(authorizedKeyPair, subjectKeyPair,
                               domain, callback) {
      var client = this; // for reference in closures

      function handleCertificate(code, headers, body) {
        if ((code != 201) || (!headers.location)) {
          callback({ error: "Unable to create certificate: "+code });
          return;
        }

        client.certificates[headers.location] = body;
        callback({
          certificate: body
        });
      }

      var csr = crypto.generateCSR(subjectKeyPair, domain);
      var request = JSON.stringify({
        csr: csr,
        authorizations: [] // TODO
      })
      var signedRequest = crypto.generateSignature(authorizedKeyPair,
                                                   new Buffer(request));
      var jsonSignedRequest = JSON.stringify(signedRequest)
      sendHttpRequest(client.newCertURL, jsonSignedRequest, handleCertificate);
    },

    revokeCertificate: function(authorizedKeyPair, certificate, callback) {
      // TODO
      /*
      function handleRevocation(response) {
        if (response.type != "revocation") {
          callback(response);
        }
        callback({ type: "success" });
      }

      var request = {
        type: "revocationRequest",
        certificate: certificate,
        signature: crypto.generateSignature(authorizedKeyPair,
                                            util.b64dec(certificate))
      };
      sendACMERequest(server, request, handleRevocation);
      */
    }
  };
}

module.exports = {
  createServer: createServer,
  createClient: createClient,

  // Convenience method on the client side
  getMeACertificate: function(newAuthz, newCert, domain, callback) {
    // Create a client for this URL and some key pairs
    var client = this.createClient(newAuthz, newCert);
    var authorizedKeyPair = client.generateKeyPair(CLIENT_KEY_SIZE);
    var subjectKeyPair = client.generateKeyPair(CLIENT_KEY_SIZE);
    var recoveryKey;

    // Authorize a key pair, then request a certificate
    client.authorizeKeyPair(authorizedKeyPair, domain, function(result) {
      DEBUG("Got callback from authorizeKeyPair:");
      DEBUG(result);
      if (result.error) {
        callback(result);
        return;
      }

      client.issueCertificate(authorizedKeyPair, subjectKeyPair,
                              domain, function(result) {
        if (result.error) {
          callback(result);
          return;
        }

        callback({
          authorizedKeyPair: authorizedKeyPair,
          subjectKeyPair: subjectKeyPair,
          certificate: util.b64enc(result.certificate)
        });
      });
    });
  },

  // Convenience methods for more nicely formatting crypto artifacts
  privateKeyToPem: function(privateKey) {
    return crypto.privateKeyToPem(privateKey);
  },

  certificateToPem: function(certificate) {
    return crypto.certificateToPem(certificate);
  },

  // Switch to enable local usage (one way)
  enableLocalUsage: function() {
    return enableLocalUsage();
  }
};

