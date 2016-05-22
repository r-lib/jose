//See: https://github.com/diafygi/webcrypto-examples
function str2buf(str) {
  var bufView = new Uint8Array(str.length);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;
}

var ecdsa = window.crypto.subtle.generateKey({
    name: "ECDSA",
    namedCurve: "P-521",
}, true, ["sign", "verify"]);

ecdsa.then(function(key){
    //Private key
    var priv = window.crypto.subtle.exportKey("jwk", key.privateKey);
    priv.then(function(str){
        console.log(JSON.stringify(str));
    });

    //Pubkey
    var pub = window.crypto.subtle.exportKey("jwk", key.publicKey);
    pub.then(function(str){
        console.log(JSON.stringify(str));
    });

    //ECDSA
    var sig = window.crypto.subtle.sign({
        name: "ECDSA",
        hash: {name: "SHA-256"},
    }, key.privateKey, str2buf("testje"));
    sig.then(function(signature){
        var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));
        console.log("sig: " + base64String);
    });
});

// signature_verify(charToRaw("testje"), sig, sha256, pubkey = pubkey)

var ecdh = window.crypto.subtle.generateKey({
    name: "ECDH",
    namedCurve: "P-521",
}, true, ["deriveKey", "deriveBits"]);

ecdh.then(function(key){
    //Private key
    var priv = window.crypto.subtle.exportKey("jwk", key.privateKey);
    priv.then(function(str){
        console.log(JSON.stringify(str));
    });

    //Pubkey
    var pub = window.crypto.subtle.exportKey("jwk", key.publicKey);
    pub.then(function(str){
        console.log(JSON.stringify(str));
    });

    //DH: OpenSSL defaults to max key length of 528 for P-521 keys
    window.crypto.subtle.deriveBits({
        name: "ECDH",
        namedCurve: "P-521",
        public: key.publicKey
    }, key.privateKey, 528).then(function(bits){
        var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(bits)));
        console.log("bits: " + base64String);
    });
});
