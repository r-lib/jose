context("Hash sizes")

test <- jwt_claim(session = "123456")
test$exp <- ceiling(test$iat + 3)

test_that("HMAC sizes", {
  secret <- "This is a secret"
  sig <- jwt_encode_hmac(test, secret, exp = 3)
  sig256 <- jwt_encode_hmac(test, secret, size = 256, exp = 3)
  sig384 <- jwt_encode_hmac(test, secret, size = 384, exp = 3)
  sig512 <- jwt_encode_hmac(test, secret, size = 512, exp = 3)
  expect_equal(sig, sig256)
  expect_gt(nchar(sig384), nchar(sig256))
  expect_gt(nchar(sig512), nchar(sig384))
  expect_equal(test, jwt_decode_hmac(sig, secret, exp = 3))
  expect_equal(test, jwt_decode_hmac(sig256, secret, exp = 3))
  expect_equal(test, jwt_decode_hmac(sig384, secret, exp = 3))
  expect_equal(test, jwt_decode_hmac(sig512, secret, exp = 3))
})


test_that("RSA sizes", {
  key <- openssl::rsa_keygen()
  pubkey <- as.list(key)$pubkey
  sig <- jwt_encode_sig(test, key, exp = 3)
  sig256 <- jwt_encode_sig(test, key, size = 256, exp = 3)
  sig384 <- jwt_encode_sig(test, key, size = 384, exp = 3)
  sig512 <- jwt_encode_sig(test, key, size = 512, exp = 3)
  expect_equal(test, jwt_decode_sig(sig, pubkey, exp = 3))
  expect_equal(test, jwt_decode_sig(sig256, pubkey, exp = 3))
  expect_equal(test, jwt_decode_sig(sig384, pubkey, exp = 3))
  expect_equal(test, jwt_decode_sig(sig512, pubkey, exp = 3))
})

test_that("EC sizes", {
  key256 <- openssl::ec_keygen("P-256")
  key384 <- openssl::ec_keygen("P-384")
  key521 <- openssl::ec_keygen("P-521")
  pubkey256 <- as.list(key256)$pubkey
  pubkey384 <- as.list(key384)$pubkey
  pubkey521 <- as.list(key521)$pubkey
  sig <- jwt_encode_sig(test, key256, exp = 3)
  sig256 <- jwt_encode_sig(test, key256, exp = 3)
  sig384 <- jwt_encode_sig(test, key384, exp = 3)
  sig512 <- jwt_encode_sig(test, key521, exp = 3)
  expect_equal(test, jwt_decode_sig(sig, pubkey256, exp = 3))
  expect_equal(test, jwt_decode_sig(sig256, pubkey256, exp = 3))
  expect_equal(test, jwt_decode_sig(sig384, pubkey384, exp = 3))
  expect_equal(test, jwt_decode_sig(sig512, pubkey521, exp = 3))
})
