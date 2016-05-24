function str2buf(str) {
  var bufView = new Uint8Array(str.length);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;
}

algos = ["AES-CTR", "AES-CBC", "AES-GCM"];
algos.forEach(function(algo){
	window.crypto.subtle.generateKey({
		name: algo,
		length: 256
	}, true,["encrypt", "decrypt"]).then(function(key){
		window.crypto.subtle.exportKey("jwk", key).then(function(keydata){
			console.log(JSON.stringify(keydata));
		});
    window.crypto.subtle.encrypt({
      name: algo,
      iv: new Uint8Array(16),
      counter: new Uint8Array(16),
      length: 128, //can be 1-128
    },key, str2buf("testje")).then(function(encrypted){
      var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(encrypted)));
      console.log("bits: " + base64String);
    });
	});
});
