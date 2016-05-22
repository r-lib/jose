//See: https://github.com/diafygi/webcrypto-examples
function str2buf(str) {
  var bufView = new Uint8Array(str.length);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;
}

var rsasig = window.crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}
}, true, ["sign", "verify"]);

rsasig.then(function(key){
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
        name: "RSASSA-PKCS1-v1_5"
    }, key.privateKey, new str2buf("testje"));
    sig.then(function(signature){
        var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));
        console.log("sig: " + base64String);
    });
});

var rasenc = window.crypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}
}, true, ["decrypt", "encrypt"]);

rasenc.then(function(key){
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

    //DH
    window.crypto.subtle.encrypt({
        name: "RSA-OAEP"
    }, key.publicKey, str2buf("testje")).then(function(bits){
        var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(bits)));
        console.log("bits: " + base64String);
    });
});
