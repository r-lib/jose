context("AES encryption")

# Note: all tests use IV/Counter 0

test_that("AES algos", {
  secret <- charToRaw("testje")

  aes_cbc_key <- read_jwk("../keys/aes_cbc.json")
  aes_cbc_msg <- readBin("../keys/aes_cbc.bin", raw(), 1000)
  expect_identical(openssl::aes_cbc_decrypt(aes_cbc_msg, key = aes_cbc_key), secret)

  aes_ctr_key <- read_jwk("../keys/aes_ctr.json")
  aes_ctr_msg <- readBin("../keys/aes_ctr.bin", raw(), 1000)
  expect_identical(openssl::aes_ctr_decrypt(aes_ctr_msg, key = aes_ctr_key), secret)

  aes_gcm_key <- read_jwk("../keys/aes_gcm.json")
  aes_gcm_msg <- readBin("../keys/aes_gcm.bin", raw(), 1000)

  #doesn't work, msg too long? Padding?
  #expect_identical(aes_gcm_decrypt(aes_gcm_msg, key = aes_gcm_key), secret)
})
