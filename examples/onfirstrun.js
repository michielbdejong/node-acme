//This example will run getMeACertificate once, each time you deploy it on a new server.
//It will save the certificate under /etc/letsencrypt on that server, and use
//it from there for the rest of the deployed server's lifetime.

var fs = require('fs'),
    mkdirp = require('mkdirp'),
    pki = require('node-forge').pki;
    acme = require('node-letsencrypt'),
    https = require('https'),
    express = require('express');

var acmeServer = 'www.letsencrypt-demo.org';
var certificatesFolder = '/etc/letsencrypt/';

function getHttpsOptionsFromDisk(domain, callback) {
  fs.readFile(certificatesFolder + domain + '/cert.pem', function(err1, certData) {
    if (err1) {
      callback(err1);
    } else {
      fs.readFile(certificatesFolder + domain + '/key.pem', function(err2, keyData) {
        if (err1) {
          callback(err1);
        } else {
          callback(null, {
            key: keyData,
            cert: certData
          });
        }
      });
    }
  });
}

function saveHttpsOptionsToDisk(domain, options, callback) {
  mkdirp(certificatesFolder + domain, function(err1) {
    if (err1) {
      callback(err1);
    } else {
      fs.writeFile(certificatesFolder + domain + '/key.pem', options.key, function (err2) {
        if (err2) {
          callback(err2);
        } else {
          fs.writeFile(certificatesFolder + domain + '/cert.pem', options.cert, function (err3) {
            callback(err3);
          });
        }
      });
    }
  });
}

function acmeResultToHttpsOptions(result) {
  return {
    key: acme.privateKeyToPem(result.subjectKeyPair.privateKey),
    cert: acme.certificateToPem(result.certificate)
  };
}

function getHttpsOptions(domain, callback) {
  fs.exists(certificatesFolder + domain, function(exists) {
    if (exists) {
      console.log('Certificate for ' + domain + ' already present in ' + certificatesFolder + domain + ', using that.');
      getHttpsOptionsFromDisk(domain, callback);
    } else {
      console.log('No certificate for ' + domain + ' yet on this server, getting one.');
      acme.getMeACertificate(acmeServer, domain, function(result) {
        var options = acmeResultToHttpsOptions(result);
        saveHttpsOptionsToDisk(domain, options, function(err) {
          if (err) {
            console.log('error saving certificate to disk!', err);
          }
          callback(null, options);
        });
      });
    }
  });
}

function startServer(domain, handler) {
  getHttpsOptions(domain, function(err, options) {
    if (err) {
      console.log('error getting certificate', err);
    } else {
      https.createServer(options, handler).listen(443);
      console.log('OK, hit me on https://' + domain + '/');
    }
  });
}

///////////////////
// vanilla usage //
///////////////////
//
//  startServer('example.com', function(req, res) {
//    res.writeHead(200);
//    res.end('Hello encrypted world\n');
//  });
//


////////////////////////
// usage with express //
////////////////////////
//
//  var app = express();
//  app.get('/', function (req, res) {
//    res.send('Hello encrypted express world\n')
//  });
//  
//  startServer('example.com', app);
//
