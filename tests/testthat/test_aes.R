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

  # GCM payload includes the authentication tag at the end
  aes_gcm_msg_body <- head(aes_gcm_msg, -16)
  aes_gcm_msg_tag <- tail(aes_gcm_msg, 16)
  expect_identical(openssl::aes_gcm_decrypt(aes_gcm_msg_body, key = aes_gcm_key,
    iv = raw(16), tag = aes_gcm_msg_tag), secret)
})
