context("Hash sizes")

test <- jwt_claim(session = "123456")

test_that("HMAC sizes", {
  secret <- "This is a secret"
  sig <- jwt_encode_hmac(test, secret)
  sig256 <- jwt_encode_hmac(test, secret, size = 256)
  sig384 <- jwt_encode_hmac(test, secret, size = 384)
  sig512 <- jwt_encode_hmac(test, secret, size = 512)
  expect_equal(sig, sig256)
  expect_gt(nchar(sig384), nchar(sig256))
  expect_gt(nchar(sig512), nchar(sig384))
  expect_equal(test, jwt_decode_hmac(sig, secret))
  expect_equal(test, jwt_decode_hmac(sig256, secret))
  expect_equal(test, jwt_decode_hmac(sig384, secret))
  expect_equal(test, jwt_decode_hmac(sig512, secret))
  expect_equal(test, jwt_decode_any(sig, secret = secret))
})


test_that("RSA sizes", {
  key <- openssl::rsa_keygen()
  pubkey <- as.list(key)$pubkey
  sig <- jwt_encode_rsa(test, key)
  sig256 <- jwt_encode_rsa(test, key, size = 256)
  sig384 <- jwt_encode_rsa(test, key, size = 384)
  sig512 <- jwt_encode_rsa(test, key, size = 512)
  expect_equal(test, jwt_decode_rsa(sig, pubkey))
  expect_equal(test, jwt_decode_rsa(sig256, pubkey))
  expect_equal(test, jwt_decode_rsa(sig384, pubkey))
  expect_equal(test, jwt_decode_rsa(sig512, pubkey))
  expect_equal(test, jwt_decode_any(sig, pubkey = pubkey))
})

test_that("EC sizes", {
  key256 <- openssl::ec_keygen("P-256")
  key384 <- openssl::ec_keygen("P-384")
  key521 <- openssl::ec_keygen("P-521")
  pubkey256 <- as.list(key256)$pubkey
  pubkey384 <- as.list(key384)$pubkey
  pubkey521 <- as.list(key521)$pubkey
  sig <- jwt_encode_ec(test, key256)
  sig256 <- jwt_encode_ec(test, key256)
  sig384 <- jwt_encode_ec(test, key384)
  sig512 <- jwt_encode_ec(test, key521)
  expect_equal(test, jwt_decode_ec(sig, pubkey256))
  expect_equal(test, jwt_decode_ec(sig256, pubkey256))
  expect_equal(test, jwt_decode_ec(sig384, pubkey384))
  expect_equal(test, jwt_decode_ec(sig512, pubkey521))
  expect_equal(test, jwt_decode_any(sig, pubkey = pubkey256))
})

