context("EC signatures and diffie hellman")

test_that("ECDSA works", {
  key <- read_jwk("../keys/ecdsa.json")
  pubkey <- read_jwk("../keys/ecdsa.pub.json")
  sig <- readBin("../keys/ecdsa.sig", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "ecdsa")
  expect_is(pubkey, "ecdsa")
  expect_identical(pubkey, as.list(key)$pubkey)

  # Does not work yet because webcrypto does not use DER format for binary data:
  # https://chromium.googlesource.com/chromium/src/+/master/components/webcrypto/algorithms/ecdsa.cc#63
  # expect_true(openssl::signature_verify(charToRaw("testje"), sig, openssl::sha256, pubkey))
  # expect_true(openssl::signature_verify("../keys/data", "../keys/ecdsa.sig", openssl::sha256, pubkey))
})

test_that("ECDH works", {
  key <- read_jwk("../keys/ecdh.json")
  pubkey <- read_jwk("../keys/ecdh.pub.json")
  bin <- readBin("../keys/ecdh.bin", raw(), 1e4)
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "ecdsa")
  expect_is(pubkey, "ecdsa")
  expect_identical(pubkey, as.list(key)$pubkey)
  expect_equal(openssl::ec_dh(key, pubkey), bin)
})

