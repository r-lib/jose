window.crypto.subtle.generateKey({
	name: "HMAC",
	hash: {"name": "SHA-256"}
}, true,["sign", "verify"]).then(function(key){
	window.crypto.subtle.exportKey("jwk", key).then(function(keydata){
		console.log(JSON.stringify(keydata));
	})
})

