algos = ["AES-CTR", "AES-CBC", "AES-GCM"];
algos.forEach(function(algo){
	window.crypto.subtle.generateKey({
		name: algo,
		length: 256
	}, true,["encrypt", "decrypt"]).then(function(key){
		window.crypto.subtle.exportKey("jwk", key).then(function(keydata){
			console.log(JSON.stringify(keydata));
		});
	});
});
