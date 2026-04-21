context("ED25519 signatures and diffie hellman")

test_that("ED25519 works", {
  key <- read_jwk("../keys/ed25519.json")
  pubkey <- read_jwk("../keys/ed25519.pub.json")
  expect_is(key, "key")
  expect_is(pubkey, "pubkey")
  expect_is(key, "ed25519")
  expect_is(pubkey, "ed25519")
  expect_identical(pubkey, as.list(key)$pubkey)

  # Roundtrip jwk
  expect_identical(key, read_jwk(write_jwk(key)))
  expect_identical(pubkey, read_jwk(write_jwk(pubkey)))

})
