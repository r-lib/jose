//See: https://github.com/diafygi/webcrypto-examples
function str2buf(str) {
  var bufView = new Uint8Array(str.length);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;
}

window.crypto.subtle.generateKey({
	name: "HMAC",
	hash: {"name": "SHA-256"}
}, true,["sign", "verify"]).then(function(key){
	window.crypto.subtle.exportKey("jwk", key).then(function(keydata){
		console.log(JSON.stringify(keydata));
	});
  window.crypto.subtle.sign({
    name: "HMAC",
  }, key, str2buf("testje")).then(function(signature){
    var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));
    console.log("bits: " + base64String);
  });
});
