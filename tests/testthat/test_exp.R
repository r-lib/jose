context("Test token expiration")

test_that("Headers work for hmac", {
  secret <- charToRaw("SuperSecret")
  privkey <- openssl::rsa_keygen()
  pubkey <- privkey$pubkey
  claim1 <- jwt_claim("test", exp = Sys.time())
  claim2 <- jwt_claim("test", exp = Sys.time()-100)
  jwth1 <- jwt_encode_hmac(claim1, secret = secret)
  jwth2 <- jwt_encode_hmac(claim2, secret = secret)
  jwtr1 <- jwt_encode_sig(claim1, privkey)
  jwtr2 <- jwt_encode_sig(claim2, privkey)
  expect_equal(jwt_decode_hmac(jwth1, secret)$iss, "test")
  expect_error(jwt_decode_hmac(jwth2, secret), "expired")
  expect_equal(jwt_decode_sig(jwtr1, pubkey)$iss, "test")
  expect_error(jwt_decode_sig(jwtr2, pubkey), "expired")
})
