context("Test JWK keys")

test_that("RSA PKCS1 signatures", {
  key <- jwk_read("../keys/rsa-pkcs1.json")
  pubkey <- jwk_read("../keys/rsa-pkcs1.pub.json")
  data <- readBin("../keys/data", raw(), 1e4)
  sig <- readBin("../keys/rsa-pkcs1.sig", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "rsa")
  expect_is(pubkey, "rsa")
  expect_identical(pubkey, as.list(key)$pubkey)
  expect_true(openssl::signature_verify(data, sig, sha256, pubkey))
  expect_true(openssl::signature_verify("../keys/data", "../keys/rsa-pkcs1.sig", sha256, pubkey))
})

test_that("RSA OAEP encryption", {
  key <- jwk_read("../keys/rsa-oaep.json")
  pubkey <- jwk_read("../keys/rsa-oaep.pub.json")
  data <- readBin("../keys/data", raw(), 1e4)
  bin <- readBin("../keys/rsa-oaep.bin", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "rsa")
  expect_is(pubkey, "rsa")
  expect_identical(data, openssl::rsa_decrypt(bin, key))
})

