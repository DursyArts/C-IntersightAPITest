function doHttpSig() {

    var navigator = {}; //fake a navigator object for the lib
    var window    = {}; //fake a window object for the lib
    
    eval(pm.collectionVariables.get("jsrsasign-js")); //import javascript jsrsasign
    
    
    function computeHttpSignature(config, headerHash) {
      var template = 'keyId="${keyId}",algorithm="${algorithm}",headers="${headers}",signature="${signature}"',
          sig = template;
    
      // compute sig here
      var signingBase = '';
      config.headers.forEach(function(h){
        if (signingBase !== '') { signingBase += '\n'; }
        signingBase += h.toLowerCase() + ": " + headerHash[h];
      });
      pm.collectionVariables.set("SsigningBase", signingBase);
  
      // Verify PEM Pre-Encapsulation Boundary
      let re = /\s*-----BEGIN (.*)-----\s+/;
      let m = config.secretkey.match(re);
      if (!m) {
        throw "Not a valid PEM pre boundary";
      }

      pem_header = m[1];
      if (pem_header == "RSA PRIVATE KEY") {
        kjursig = new KJUR.crypto.Signature({"alg": "SHA256withRSA"});
      } else if (pem_header == "EC PRIVATE KEY") {
        config.secretkey = config.secretkey.replaceAll(pem_header, 'PRIVATE KEY');
        kjursig = new KJUR.crypto.Signature({"alg": "SHA256withECDSA"});
      } else {
        throw `Unsupported key: ${pem_header}`;
      }
      kjursig.init(config.secretkey);
      kjursig.updateString(signingBase);
      var hash = kjursig.sign();

      kjursig.updateString("Test");
      var testest = kjursig
      pm.collectionVariables.set("updateString", kjursig.getMessage);
      pm.collectionVariables.set("singningBase", kjursig.raw);
      var hash2 = kjursig.sign();
        pm.collectionVariables.set("hash Test", hash2);
      var signatureOptions = {
            keyId : config.keyId,
            algorithm: config.algorithm,
            headers: config.headers,
            signature : hextob64(hash)
          };
    pm.collectionVariables.set("signature", hextob64(hash2));
      // build sig string here
      Object.keys(signatureOptions).forEach(function(key) {
        var pattern = "${" + key + "}",
            value = (typeof signatureOptions[key] != 'string') ? signatureOptions[key].join(' ') : signatureOptions[key];
        sig = sig.replace(pattern, value);
      });

      pm.collectionVariables.set("sig", sig);
      return sig;

      
    }

    // Resolve all the Postman variables that are part of the request or URI
    let sdk = require('postman-collection');
    let newRequest = new sdk.Request(pm.request.toJSON());
    let resolvedRequest = newRequest.toObjectResolved(
        null, [pm.variables.toObject()], { ignoreOwnVariables: true }
        );
    
    
    var body = "";
    if (
        request.method.toLowerCase() == "get" ||
        request.method.toLowerCase() == "delete" ) {
        body="";
    } else {
        body=resolvedRequest.body.raw;
    }

    var computedDigest = 'SHA-256=' + CryptoJS.enc.Base64.stringify(CryptoJS.SHA256(body));
    
    var curDate = new Date().toGMTString();
    var targetUrl = "/" + resolvedRequest.url.path.join("/");
    var host = resolvedRequest.url.host.join(".");
    
    // Process Query String
    var queryString  = "";
    var paramCount = 0;
    pm.request.url.query.all().forEach( (param) => {
        // Append each URL encoded parameter to the targetUrl
        // However unencode Commas (,), Colons (:), Dollar Signs (:)
        // and Forward Slashes (/)
        if (!param.disabled) {
            if (paramCount > 0) {
                queryString += '&';
            }
            paramCount++;
            // Append each URL encoded parameter to the targetUrl unencode 
            // 24 $ Dollar Sign
            // 28 ( Left Parenthesis 
            // 29 ) Right Parenthesis
            // 2B + Plus Sign
            // 2C , Comma
            // 2F / Forward Slash
            // 3A : Colon
            // 3D = Equals Sign
            // 40 @ At Sign
            //

            // Replace any variables within params with COLLECTION variable
            let paramValue = param.value;
            let replaceVars = paramValue.match(/\{\{[\w\-]+\}\}/g);
            if(replaceVars) {
                replaceVars.forEach(replaceVar => {
                    paramValue = paramValue.replace(replaceVar, pm.variables.get(replaceVar.replace('{{', '').replace('}}', '')));
                })
            }
            
            queryString += (
                param.key + "=" +
                encodeURIComponent(paramValue).
                replace(/['()=]/g, escape).
                replace(/%(?:24|28|29|2B|2C|2F|3A|3D|40)/g, unescape)
            );
        }
    });
    
    if (queryString.length > 0) {
        queryStringTmp = queryString.replace("%25","%")
        targetUrl += "?" + queryStringTmp;
        console.log("Target Url: " + targetUrl );
    }
    
    var headerHash = {
          date : curDate,
          digest : computedDigest,
          host : host,
          '(request-target)' : request.method.toLowerCase() + ' ' + targetUrl
        };
    
    var configHash = {
          algorithm : 'hs2019',
          keyId : environment['api-key'],
          secretkey : environment['secret-key'],
          headers : [ '(request-target)', 'date', 'digest', 'host' ]
        };
    var sig = computeHttpSignature(configHash, headerHash);
    pm.collectionVariables.set('httpsig', sig);
    pm.collectionVariables.set('computed-digest', computedDigest);
    pm.collectionVariables.set("current-date", curDate);
    pm.collectionVariables.set("target-url", targetUrl);
    
    pm.request.headers.add({
        key: 'Accept',
        value: 'application/json'
    });
    pm.request.headers.add({
        key: 'Accept',
        value: 'application/json'
    });
    pm.request.headers.add({
        key: 'Authorization',
        value: `Signature ${sig}`
    });
    pm.request.headers.add({
        key: 'Digest',
        value: computedDigest
    });
    pm.request.headers.add({
        key: 'Date',
        value: curDate
    });
    pm.request.headers.add({
        key: 'Content-Type',
        value: 'application/json'
    });
}

if (pm.collectionVariables.get('jsrsasign-js') === undefined || pm.collectionVariables.get('jsrsasign-js') == "") {
    console.log("jsrasign library not already downloaded. Downloading now. ");
    
    pm.sendRequest({
        url: "http://kjur.github.io/jsrsasign/jsrsasign-latest-all-min.js",
        method: "GET",
        body: {}
    }, function (err, res) {
        console.log(res.text());
        pm.collectionVariables.set("jsrsasign-js", res.text());
        doHttpSig();
    });
    
} else {
    doHttpSig();
}
