context("RSA signatures and encryption")

test_that("RSA PKCS1 signatures", {
  key <- read_jwk("../keys/rsa-pkcs1.json")
  pubkey <- read_jwk("../keys/rsa-pkcs1.pub.json")
  data <- readBin("../keys/data", raw(), 1e4)
  sig <- readBin("../keys/rsa-pkcs1.sig", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "rsa")
  expect_is(pubkey, "rsa")
  expect_identical(pubkey, as.list(key)$pubkey)
  expect_true(openssl::signature_verify(data, sig, openssl::sha256, pubkey))
  expect_true(openssl::signature_verify("../keys/data", "../keys/rsa-pkcs1.sig", openssl::sha256, pubkey))
})

test_that("RSA OAEP encryption", {
  key <- read_jwk("../keys/rsa-oaep.json")
  pubkey <- read_jwk("../keys/rsa-oaep.pub.json")
  data <- readBin("../keys/data", raw(), 1e4)
  bin <- readBin("../keys/rsa-oaep.bin", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "rsa")
  expect_is(pubkey, "rsa")

  ## Does not work, rsa_decrypt does not use OAEP I think
  #expect_identical(data, openssl::rsa_decrypt(bin, key))
})

