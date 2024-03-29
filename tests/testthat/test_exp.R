context("Test token expiration")

test_that("Headers work for hmac", {
  secret <- charToRaw("SuperSecret")
  privkey <- openssl::rsa_keygen()
  pubkey <- privkey$pubkey
  claim1 <- jwt_claim("test", exp = Sys.time())
  claim2 <- jwt_claim("test", exp = Sys.time() - 100)
  claim3 <- jwt_claim("test", nbf = Sys.time())
  claim4 <- jwt_claim("test", nbf = Sys.time() + 100)
  jwth1 <- jwt_encode_hmac(claim1, secret = secret)
  jwth2 <- jwt_encode_hmac(claim2, secret = secret)
  jwth3 <- jwt_encode_hmac(claim3, secret = secret)
  jwth4 <- jwt_encode_hmac(claim4, secret = secret)
  jwtr1 <- jwt_encode_sig(claim1, privkey)
  jwtr2 <- jwt_encode_sig(claim2, privkey)
  jwtr3 <- jwt_encode_sig(claim3, privkey)
  jwtr4 <- jwt_encode_sig(claim4, privkey)
  expect_equal(jwt_decode_hmac(jwth1, secret)$iss, "test")
  expect_error(jwt_decode_hmac(jwth2, secret), "expired")
  expect_equal(jwt_decode_hmac(jwth3, secret)$iss, "test")
  expect_error(jwt_decode_hmac(jwth4, secret), "before")
  expect_equal(jwt_decode_sig(jwtr1, pubkey)$iss, "test")
  expect_error(jwt_decode_sig(jwtr2, pubkey), "expired")
  expect_equal(jwt_decode_sig(jwtr3, pubkey)$iss, "test")
  expect_error(jwt_decode_sig(jwtr4, pubkey), "before")
})
