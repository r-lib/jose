context("Test JWK keys")

test_that("ECDSA works", {
  key <- jwk_read("../keys/ecdsa.json")
  pubkey <- jwk_read("../keys/ecdsa.pub.json")
  sig <- readBin("../keys/ecdsa.sig", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "ecdsa")
  expect_is(pubkey, "ecdsa")
  expect_identical(pubkey, as.list(key)$pubkey)
  expect_true(openssl::signature_verify(charToRaw("testje"), sig, sha256, pubkey))
  expect_true(openssl::signature_verify("../keys/data", "../keys/ecdsa.sig", sha256, pubkey))
})

test_that("ECDH works", {
  key <- jwk_read("../keys/ecdh.json")
  pubkey <- jwk_read("../keys/ecdh.pub.json")
  bin <- readBin("../keys/ecdh.bin", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "ecdsa")
  expect_is(pubkey, "ecdsa")
  expect_identical(pubkey, as.list(key)$pubkey)
  expect_equal(openssl::ec_dh(key, pubkey), bin)
})

