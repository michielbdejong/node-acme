var async  = require("async");
var http   = require("http");
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
const MAX_POLL              =    10;
const VALIDATION_METHOD     = "simpleHttps";
const DVSNI_SUFFIX          = ".acme.invalid";

// By default, assume we're on heroku
// Local usage requires:
// * Different ports
// * Connecting to localhost in *Validation below
var ENABLE_LOCAL_USAGE = false;
var VALIDATION_DEFAULT_PORT = 5001;
var VALIDATION_CLIENT_PORT =  80;
var VALIDATION_SERVER_PORT =  process.env.PORT;

function enableLocalUsage() {
  ENABLE_LOCAL_USAGE = true;
  VALIDATION_CLIENT_PORT = VALIDATION_DEFAULT_PORT;
  VALIDATION_SERVER_PORT = VALIDATION_DEFAULT_PORT;
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

/***** Server helper methods *****/

function Error(code, message) {
  return {
    type: "error",
    error: code,
    message: message
  };
}

function MalformedRequestError() {
  return Error("malformed", "Malformed ACME request");
}

function NotFoundError() {
  return Error("notFound", "Requested token not found");
}

function NotSupportedError() {
  return Error("notSupported", "Requested function not supported by this server");
}

function ForbiddenError() {
  return Error("forbidden", "Requested action would violate the server's policy");
}

function UnauthorizedError(message) {
  return Error("unauthorized", message);
}

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

function createValidationProcess(domain, challenge, response) {
  switch (challenge.type) {
    case "simpleHttps":
      return SimpleHttpsValidation(domain, challenge, response);
    case "dvsni":
      return DvsniValidation(domain, challenge, response);
  }
  return null;
}

function SimpleHttpsChallenge() {
  return {
    type: "simpleHttps",
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
  return http.createServer(function(req, resp) {
    if ((req.headers.host == domain) &&
        (req.url == "/.well-known/acme-challenge/" + response.path)) {
      resp.writeHead(200, "OK", { "content-type": "text/plain" });
      resp.write(challenge.token);
    } else {
      resp.writeHead(404, "Not Found");
    }
    resp.end();
  });
}

function SimpleHttpsValidation(domain, challenge, response) {
  var token = challenge.token;
  var path = response.path;

  var connectDomain = (ENABLE_LOCAL_USAGE)? "localhost" : domain;
  var options = {
    host: connectDomain,
    port: VALIDATION_CLIENT_PORT,
    path: "/.well-known/acme-challenge/" + path,
    headers: { "host": domain }
  };

  return function(callback) {
    var req = http.request(options, function(response) {
      var body = "";
      response.on("data", function(chunk) {
        body += chunk.toString();
      });
      response.on("end", function() {
        DEBUG("Got token=["+ body +"], expecting=["+ token +"]")
        callback(null, (body == token));
      });
    });
    req.on("error", function(error) {
      DEBUG("Error making validation HTTP request");
      DEBUG(error);
      callback(error, null);
    });
    req.end();
  }
}

function DvsniChallenge() {
  return {
    type: "dvsni",
    r: crypto.randomString(32),
    nonce: util.b64dec(crypto.randomString(16)).toString("hex")
  }
}

function DvsniResponse(challenge) {
  return {
    type: "dvsni",
    s: crypto.randomString(32)
  }
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

function DvsniValidation(domain, challenge, response) {
  // Do all the crypto computations we need
  var nonceName = challenge.nonce + DVSNI_SUFFIX;
  var RS = Buffer.concat([util.b64dec(challenge.r), util.b64dec(response.s)]);
  var zName = crypto.sha256(RS).toString("hex") + DVSNI_SUFFIX;

  var connectDomain = (ENABLE_LOCAL_USAGE)? "localhost" : domain;
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
    keyPair: null,
    certificate: null,
    issuedChallenges: {},    // Nonce  -> { domain, challenge }
    authorizedKeys: {},      // Domain -> [ Keys ]
    recoveryKeys: {},        // Key    -> Domain
    certificates: {},        // Serial -> Certificate
    revocationStatus: {},    // Certificate -> boolean
    deferredResponses: {}    // Token  -> Response
  }

  // If state is provided, use it
  if (state_in) {
    for (key in state_in) {
      state[key] = state_in[key];
    }
  }

  // Generate a key pair if we need to
  if (!state.keyPair) {
    state.keyPair = crypto.generateKeyPair(CA_KEY_SIZE);
  }

  // ACME message handlers
  function handleChallengeRequest(message) {
    if (!util.fieldsPresent(["identifier"], message)) {
      return MalformedRequestError();
    }

    // Rough test for domain name syntax and IP addresses
    var identifier = message.identifier;
    if (!identifier) {
      return MalformedRequestError();
    }
    if (forbiddenIdentifier(identifier)) {
      return ForbiddenError();
    }

    // Generate random nonce and challenge(s), and keep state
    var nonce = crypto.randomString(32);
    var challenges = [ createChallenge(VALIDATION_METHOD) ];
    state.issuedChallenges[nonce] = {
      identifier: identifier,
      challenges: challenges
    };

    // Return nonce, challenge
    return {
      type: "challenge",
      nonce: nonce,
      challenges: challenges,

      // XXX: We don't actually use this; we key off the nonce
      // The session ID is mainly useful in future scenarios where
      // there can be multiple challenge/response round-trips.
      sessionID: crypto.randomString(32),
    };
  }

  function handleAuthorizationRequest(message) {
    if (!("signature" in message) || !("nonce" in message) ||
        (!("responses" in message) && !("recoveryKey" in message)) ||
        !util.isB64String(message.nonce) ||
        !util.validSignature(message.signature)) {
      return MalformedRequestError();
    }

    // Retrieve state
    var serverNonce = message.nonce;
    if (!(serverNonce in state.issuedChallenges)) {
      return NotFoundError();
    }
    var challenge = state.issuedChallenges[serverNonce];
    var identifier = challenge.identifier;

    // Verify signature over identifier+nonce before going further
    var identifierInput = new Buffer(identifier, "utf8");
    var serverNonceInput = util.b64dec(serverNonce);
    var signatureInput = Buffer.concat([identifierInput, serverNonceInput]);
    if (!crypto.verifySignature(message.signature, signatureInput)) {
      return UnauthorizedError();
    }

    var successResponse = {
      type: "authorization",
      identifier: identifier,
      jwk: message.signature.jwk,
    }

    // If recoveryKey provided ...
    if ("recoveryKey" in message) {
      var key = message.recoveryKey;
      if ((key in state.recoveryKeys) &&
          (state.recoveryKeys[key] == identifier)) {
        // Recovery key is authorized
        if (!(identifier in state.authorizedKeys)) {
          state.authorizedKeys[identifier] = [];
        }

        state.authorizedKeys[identifier].push(util.keyFingerprint(message.signature.jwk));
        return successResponse;
      }

      // XXX: In the case of an unrecognized/bad key, we fall back
      // to validation.  This seems ok, since there might be state
      // mismatch.  It might be worth teasing apart these cases.
    }

    // Else queue async task to verify, and send a deferral response
    if (typeof(message.responses) != "object" ||
        message.responses.length != challenge.challenges.length) {
      return MalformedRequestError();
    }

    var deferralToken = crypto.newToken();
    var deferralResponse = {
      type: "defer",
      token: deferralToken,
      message: "Validating identifier..."
    }
    state.deferredResponses[deferralToken] = deferralResponse;

    // Queue up validation processes
    var validationProcesses = [];
    for (i in challenge.challenges) {
      validationProcesses.push(createValidationProcess(
                                  identifier,
                                  challenge.challenges[i],
                                  message.responses[i]));
    }

    if (validationProcesses.length == 0) {
      return UnauthorizedError("No acceptable challenge response found");
    }

    async.parallel(validationProcesses,
      function(err, results) {
        // Validation succeds if any test succeeds
        validationResult = false;
        for (i in results) {
          validationResult = validationResult || results[i];
        }

        if (validationResult) {
          // Remember authorized key
          if (!(identifier in state.authorizedKeys)) {
            state.authorizedKeys[identifier] = [];
          }
          state.authorizedKeys[identifier].push(util.keyFingerprint(message.signature.jwk));

          // Set a new recovery key
          var newRecoveryKey = crypto.newToken();
          state.recoveryKeys[newRecoveryKey] = identifier;
          successResponse.recoveryKey = newRecoveryKey;

          // Provision the success response
          delete state.deferredResponses[deferralToken];
          state.deferredResponses[deferralToken] = successResponse;
        } else {
          delete state.deferredResponses[deferralToken];
          state.deferredResponses[deferralToken] = UnauthorizedError("Could not validate");
        }
      }
    );

    return deferralResponse;
  }

  function handleCertificateRequest(message) {
    if (!util.fieldsPresent(["csr", "signature"], message) ||
        !util.isB64String(message.csr) ||
        !util.validSignature(message.signature)) {
      return MalformedRequestError();
    }

    // Validate signature by authorization key
    var signatureInput = new Buffer(message.csr, "base64");
    if (!crypto.verifySignature(message.signature, signatureInput)) {
      return UnauthorizedError();
    }

    // Validate CSR and extract domains
    var identifier = crypto.verifiedCommonName(message.csr);
    if (!identifier || !(identifier in state.authorizedKeys)) {
      return MalformedRequestError();
    }

    // Validate that authorization key is authorized for all domains
    var keys = state.authorizedKeys[identifier];
    if (keys.indexOf(util.keyFingerprint(message.signature.jwk)) < 0) {
      return UnauthorizedError();
    }

    // Create certificate
    do {
      serialNumber = crypto.randomSerialNumber();
    } while (serialNumber in state.certificates);
    var certificate = crypto.generateCertificate({
      distinguishedName: state.distinguishedName,
      keyPair: state.keyPair
    }, serialNumber, message.csr);

    // Store state about this certificate
    state.certificates[serialNumber] = certificate;
    state.revocationStatus[certificate] = false;

    return {
      type: "certificate",
      certificate: certificate,
    };
  }

  function handleRevocationRequest(message) {
    if (!util.fieldsPresent(["certificate", "signature"], message) ||
        !util.isB64String(message.certificate) ||
        !util.validSignature(message.signature)) {
      return MalformedRequestError();
    }

    var signatureInput = util.b64dec(message.certificate);
    if (!crypto.verifySignature(message.signature, signatureInput)) {
      return UnauthorizedError();
    }

    state.revocationStatus[message.certificate] = true;
    return { "type": "revocation" };
  }

  function handleStatusRequest(message) {
    if (!message.token) { return MalformedRequestError(); }
    if (!state.deferredResponses[message.token]) { return NotFoundError(); }

    response = state.deferredResponses[message.token];
    if (response.type != "defer") {
      delete state.deferredResponses[message.token];
    }
    return response;
  }

  function handleDumpStateRequest(message) {
    return {
      "type": "stateDump",
      "state": state
    }
  }

  function handleAcmeMessage(message) {
    if (typeof(message) != "object" || !message.type) {
      response.writeHead(400, "Bad Request");
      response.end();
      return;
    }

    var reply;
    switch (message.type) {
      case "challengeRequest":
        reply = handleChallengeRequest(message); break;
      case "authorizationRequest":
        reply = handleAuthorizationRequest(message); break;
      case "certificateRequest":
        reply = handleCertificateRequest(message); break;
      case "revocationRequest":
        reply = handleRevocationRequest(message); break;
      case "statusRequest":
        reply = handleStatusRequest(message); break;
      case "dumpStateRequest":
        reply = handleDumpStateRequest(message); break;
      default:
        reply = {
          type: "error",
          error: "notSupported",
          message:"Message type "+ message.type +"not supported"
        }
    }

    return reply;
  }

  // The main dispatch method and actual HTTP server
  function handleAcmeRequest(request, response){
    // Check that the method is POST
    if (request.method != "POST") {
      response.writeHead(405, "Invalid method");
      response.end();
      return;
    }

    // TODO: Any other checks on request

    // Read parse message body, parse and dispatch
    var jsonMessage = "";
    request.on("data", function(chunk) {
      jsonMessage += chunk.toString();
    });
    request.on("end", function() {
      log.push(jsonMessage);

      var message;
      try {
        message = JSON.parse(jsonMessage);
      } catch (e) {
        response.writeHead(400, "Bad Request");
        response.end();
        return;
      }

      // Perform the actual ACME logic
      var reply = handleAcmeMessage(message);

      var jsonReply = JSON.stringify(reply);
      log.push(jsonReply);
      response.writeHead(200, "OK");
      response.write(jsonReply);
      response.end();
    });
  }

  var server = http.createServer(handleAcmeRequest);

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
      console.log(state.distinguishedName);
    },

    listen: function(port) {
      return server.listen(port);
    },

    close: function() {
      return server.close();
    },

    handleAcmeMessage: function(request, response) {
      return handleAcmeMessage(request, response);
    }
  }
}


/***** Client helper methods *****/

// Simple HTTP request method
function sendRequest(server, message, callback) {
  var req = http.request(server, function(res) {
    var buffer = "";
    var error = false;
    if (res.statusCode != 200) {
      error = true;
      callback(null, res.statusCode);
    }

    res.setEncoding('utf8');
    res.on('data', function(chunk) {
      buffer += chunk.toString();
    });
    res.on('end', function() {
      DEBUG(buffer);
      if (!error) { callback(buffer); }
    });
  });

  req.on('error', function(error) {
    callback(null, error);
  });
  DEBUG(message);
  req.write(message);
  req.end();
}

// Defer-aware request/response
function sendACMERequest(server, request, callback) {
  var jsonRequest = JSON.stringify(request);

  var polls = 0;
  function handlePossibleDefer(jsonResponse, error) {
    if (error) {
      callback({ type: "error", code: "http" });
      return;
    }

    response = JSON.parse(jsonResponse);
    if (!("type" in response)) {
      callback({ type: "error", code: "malformedResponse" });
      return;
    }

    if (response.type == "defer") {
      var interval = DEFAULT_POLL_INTERVAL;
      if (("interval" in response) && (typeof(response.interval) == "number")) {
        interval = response.interval * 1000;
        interval = (interval > MAX_POLL_INTERVAL)? MAX_POLL_INTERVAL : interval;
        interval = (interval < MIN_POLL_INTERVAL)? MIN_POLL_INTERVAL : interval;
      }

      var jsonStatusRequest = JSON.stringify({
        type: "statusRequest",
        token: response.token
      });
      polls += 1;
      if (polls > MAX_POLL) {
          callback({
          type: "error",
          error: "timeout"
        });
        return;
      }

      setTimeout(function() {
        sendRequest(server, jsonStatusRequest, handlePossibleDefer);
      }, interval);
      return;
    }

    callback(response);
  }

  sendRequest(server, jsonRequest, handlePossibleDefer)
}

/**
 *  createClient(serverURL)
 *
 *  Creates an ACME client object that implements ACME certificate
 *  management functions.  The only input is the URL for the ACME server.
 *
 *  Methods:
 *    * generateKeyPair(bits) => { publicKey: ..., privateKey: ...}
 *    * authorizeKeyPair(keyPair, domain) => { recoveryKey: ... }
 *    * issueCertificate(authorizedKeyPair, subjectKeyPair, domain) => cert
 *    * revokeCertificate(authorizedKeyPair, cert) => boolean
 *
 *  Notes:
 *    * All methods take a callback as final argument
 *    * Callback will be called with an object encoding the result
 *      { type: "success", ... }
 *      { type: "error", ... }
 **/
function createClient(serverURL) {
  // TODO: Parse URL into server params
  var parsedURL = url.parse(serverURL);
  var server = {
    host: parsedURL.hostname,
    port: parsedURL.port,
    path: parsedURL.path,
    method: "POST",
    headers: {
      "Content-Type": "text/json"
    }
  };

  return {
    generateKeyPair: crypto.generateKeyPair,

    authorizeKeyPair: function(keyPair, domain, callback) {
      var tempServer = null;

      function handleChallenge(response) {
        // Parse response
        if (response.type != "challenge") {
          callback(response);
          return;
        }

        // Respond to first simpleHttps or DVSNI challenge
        var responses = [];
        var found = false;
        for (var i=0; i < response.challenges.length  ; ++i) {
          if (!found &&
              (response.challenges[i].type == "simpleHttps") ||
              (response.challenges[i].type == "dvsni")) {
            found = true;
            var challenge = response.challenges[i];
            var challengeResponse = createResponse(challenge);
            tempServer = createValidationServer(domain, challenge,
                                                challengeResponse);
            responses.push(challengeResponse);
          } else {
            responses.push(null);
          }
        }

        // Start the validation server
        if (tempServer) {
          try {
            tempServer.listen(VALIDATION_SERVER_PORT);
          } catch (e) {
            // Most commonly, couldn't bind to the port
            return {
              type: "error",
              error: "http",
              message: "Unable to bind temp server to a port"
            }
          }
        }

        // Construct new request
        var sigInput = Buffer.concat([new Buffer(domain),
                                      util.b64dec(response.nonce)]);
        var request = {
          type: "authorizationRequest",
          nonce: response.nonce,
          signature: crypto.generateSignature(keyPair, sigInput),
          responses: responses
        }

        // Carry forward the session ID, if present
        if (response.sessionID) {
          request.sessionID = response.sessionID;
        }

        sendACMERequest(server, request, handleAuthorization);
      }

      function handleAuthorization(response) {
        // Shut down validation server regardless of response
        if (tempServer) {
          tempServer.close();
        }

        if (response.type != "authorization") {
          callback(response);
          return;
        }

        callback({
          type: "success",
          recoveryKey: response.recoveryKey
        });
      }

      var request = {
        type: "challengeRequest",
        identifier: domain
      };
      sendACMERequest(server, request, handleChallenge);
    },

    issueCertificate: function(authorizedKeyPair, subjectKeyPair,
                               domain, callback) {
      function handleCertificate(response) {
        if (response.type != "certificate") {
          callback(response);
          return;
        }

        callback({
          type: "success",
          certificate: response.certificate
        });
      }

      var csr = crypto.generateCSR(subjectKeyPair, domain);
      var request = {
        type: "certificateRequest",
        csr: csr,
        signature: crypto.generateSignature(authorizedKeyPair, util.b64dec(csr))
      };
      sendACMERequest(server, request, handleCertificate);
    },

    revokeCertificate: function(authorizedKeyPair, certificate, callback) {
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
    }
  }
}

module.exports = {
  createServer: createServer,
  createClient: createClient,

  // Convenience method on the client side
  getMeACertificate: function(url, domain, callback) {
    // Create a client for this URL and some key pairs
    var client = this.createClient(url);
    var authorizedKeyPair = client.generateKeyPair(CLIENT_KEY_SIZE);
    var subjectKeyPair = client.generateKeyPair(CLIENT_KEY_SIZE);
    var recoveryKey;

    // Authorize a key pair, then request a certificate
    client.authorizeKeyPair(authorizedKeyPair, domain, function(result) {
      if (result.type == "error") {
        callback(result);
        return;
      }
      recoveryKey = result.recoveryKey;

      client.issueCertificate(authorizedKeyPair, subjectKeyPair,
                              domain, function(result) {
        if (result.type == "error") {
          callback(result);
          return;
        }

        callback({
          authorizedKeyPair: authorizedKeyPair,
          subjectKeyPair: subjectKeyPair,
          recoveryKey: recoveryKey,
          certificate: result.certificate
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
