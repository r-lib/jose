context("JWE encryption")

plaintext <- paste0(
  "You can trust us to stick with you through thick and ",
  "thin–to the bitter end. And you can trust us to ",
  "keep any secret of yours–closer than you keep it ",
  "yourself. But you cannot trust us to let you face trouble ",
  "alone, and go off without a word. We are your friends, Frodo.")

test_that("JWE examples from RFC 7520", {
  examples <- jsonlite::fromJSON("../keys/rfc7520_jwe.json", simplifyVector = FALSE)
  expect_length(examples, 5)
  for(x in examples){
    key <- read_jwk(x$key)
    out <- jwe_decrypt(x$jwe, key)
    expect_identical(out, charToRaw(enc2utf8(plaintext)))
  }
})

test_that("JWE roundtrip for all algorithms", {
  encs <- c("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")
  rsa <- openssl::rsa_keygen()
  keys <- list(
    "RSA-OAEP" = rsa,
    "RSA-OAEP-256" = rsa,
    "ECDH-ES" = openssl::ec_keygen("P-256"),
    "ECDH-ES+A128KW" = openssl::ec_keygen("P-384"),
    "ECDH-ES+A192KW" = openssl::ec_keygen("P-521"),
    "ECDH-ES+A256KW" = openssl::ec_keygen("P-256"),
    "A128KW" = openssl::rand_bytes(16),
    "A192KW" = openssl::rand_bytes(24),
    "A256KW" = openssl::rand_bytes(32)
  )
  for(alg in names(keys)){
    key <- keys[[alg]]
    pubkey <- if(is.raw(key)) key else as.list(key)$pubkey
    for(enc in encs){
      token <- jwe_encrypt(plaintext, pubkey, alg = alg, enc = enc)
      header <- jsonlite::fromJSON(rawToChar(base64url_decode(strsplit(token, ".", fixed = TRUE)[[1]][1])))
      expect_equal(header$alg, alg)
      expect_equal(header$enc, enc)
      expect_equal(rawToChar(jwe_decrypt(token, key)), enc2utf8(plaintext))
    }
  }
  for(enc in encs){
    secret <- openssl::rand_bytes(jose:::jwe_enc_keylen(enc))
    token <- jwe_encrypt(plaintext, secret, alg = "dir", enc = enc)
    expect_equal(rawToChar(jwe_decrypt(token, secret)), enc2utf8(plaintext))
  }
})

test_that("JWE default alg depends on key", {
  alg_of <- function(token) jsonlite::fromJSON(rawToChar(base64url_decode(strsplit(token, ".", fixed = TRUE)[[1]][1])))$alg
  expect_equal(alg_of(jwe_encrypt("x", as.list(openssl::rsa_keygen())$pubkey)), "RSA-OAEP-256")
  expect_equal(alg_of(jwe_encrypt("x", as.list(openssl::ec_keygen())$pubkey)), "ECDH-ES")
  expect_equal(alg_of(jwe_encrypt("x", openssl::rand_bytes(16))), "A128KW")
  expect_equal(alg_of(jwe_encrypt("x", openssl::rand_bytes(32))), "A256KW")
})

test_that("JWE detects tampering and wrong keys", {
  for(enc in c("A256GCM", "A128CBC-HS256")){
    key <- openssl::ec_keygen()
    token <- jwe_encrypt("secret message", as.list(key)$pubkey, enc = enc)
    parts <- strsplit(token, ".", fixed = TRUE)[[1]]
    expect_equal(rawToChar(jwe_decrypt(token, key)), "secret message")

    header <- jsonlite::fromJSON(rawToChar(base64url_decode(parts[1])), simplifyVector = FALSE)
    header$kid <- "foo"
    bad <- paste(c(base64url_encode(jsonlite::toJSON(header, auto_unbox = TRUE)), parts[-1]), collapse = ".")
    expect_error(jwe_decrypt(bad, key), "JWE decryption failed")

    ct <- base64url_decode(parts[4])
    ct[1] <- xor(ct[1], as.raw(1))
    bad <- paste(c(parts[1:3], base64url_encode(ct), parts[5]), collapse = ".")
    expect_error(jwe_decrypt(bad, key), "JWE decryption failed")

    tag <- base64url_decode(parts[5])
    bad <- paste(c(parts[1:4], base64url_encode(tag[1:8])), collapse = ".")
    expect_error(jwe_decrypt(bad, key), "JWE decryption failed")

    expect_error(jwe_decrypt(token, openssl::ec_keygen()), "JWE decryption failed")
  }
  secret <- openssl::rand_bytes(32)
  token <- jwe_encrypt("secret message", secret)
  expect_error(jwe_decrypt(token, openssl::rand_bytes(32)), "JWE decryption failed")
  key <- openssl::rsa_keygen()
  token <- jwe_encrypt("secret message", as.list(key)$pubkey)
  expect_error(jwe_decrypt(token, openssl::rsa_keygen()), "JWE decryption failed")
})

test_that("JWE input validation", {
  secret <- openssl::rand_bytes(32)
  expect_error(jwe_encrypt("x", secret, alg = "RSA-OAEP"), "requires a RSA key")
  expect_error(jwe_encrypt("x", secret, alg = "A128KW"), "must be 16 bytes")
  expect_error(jwe_encrypt("x", secret, alg = "dir", enc = "A128GCM"), "must be 16 bytes")
  expect_error(jwe_encrypt("x", secret, alg = "RSA1_5"), "Unsupported alg")
  expect_error(jwe_encrypt("x", secret, enc = "A128CBC"), "Unsupported enc")
  expect_error(jwe_encrypt("x", secret, header = list(alg = "dir")), "alg and enc arguments")
  token <- jwe_encrypt("x", secret)
  expect_error(jwe_decrypt(token, openssl::rsa_keygen()), "requires a raw")
  expect_error(jwe_decrypt("a.b.c", secret), "5 parts")
})

test_that("JWE with header fields and apu/apv", {
  key <- openssl::ec_keygen("P-384")
  header <- list(kid = "mykey", apu = base64url_encode(charToRaw("Alice")), apv = base64url_encode(charToRaw("Bob")))
  token <- jwe_encrypt("hello", as.list(key)$pubkey, alg = "ECDH-ES+A256KW", header = header)
  parts <- strsplit(token, ".", fixed = TRUE)[[1]]
  h <- jsonlite::fromJSON(rawToChar(base64url_decode(parts[1])))
  expect_equal(h$kid, "mykey")
  expect_equal(h$apu, header$apu)
  expect_equal(rawToChar(jwe_decrypt(token, key)), "hello")
})

test_that("Encrypted JWT", {
  key <- openssl::rsa_keygen()
  claim <- jwt_claim(name = "jeroen", session = 123456)
  token <- jwt_encrypt(claim, as.list(key)$pubkey)
  h <- jsonlite::fromJSON(rawToChar(base64url_decode(strsplit(token, ".", fixed = TRUE)[[1]][1])))
  expect_equal(h$typ, "JWT")
  out <- jwt_decrypt(token, key)
  expect_s3_class(out, "jwt_claim")
  expect_equal(out$name, "jeroen")
  expect_equal(out$session, 123456)

  expired <- jwt_claim(exp = as.numeric(Sys.time()) - 3600)
  token <- jwt_encrypt(expired, as.list(key)$pubkey)
  expect_error(jwt_decrypt(token, key), "expired")
})
