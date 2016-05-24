context("HMAC signature")

test_that("ECDSA works", {
  key <- jwk_read("../keys/hmac.json")
  sig <- readBin("../keys/hmac.sig", raw(), 100)
  expect_identical(sig, unclass(openssl::sha256(charToRaw("testje"), key = key)))
})
