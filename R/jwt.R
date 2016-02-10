jwt_encode_hs256 <- function(payload = list(), secret = "secret") {
  header <- '{"alg":"HS256", "typ":"JWT"}'
  body <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  doc <- paste(base64url_encode(header), base64url_encode(body), sep = ".")
  sig <- sha256(charToRaw(doc), key = secret)
  paste(doc, base64url_encode(sig), sep = ".")
}

jwt_encode_rs256 <- function(payload = list(), key = openssl::my_key()) {
  header <- '{"alg":"RS256", "typ":"JWT"}'
  body <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  doc <- paste(base64url_encode(header), base64url_encode(body), sep = ".")
  sig <- signature_create(charToRaw(doc), sha256, key = key)
  paste(doc, base64url_encode(sig), sep = ".")
}

jwt_decode_hs256 <- function(jwt, secret){
  # Verify input
  input <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  stopifnot(length(input) == 3)
  header <- jsonlite::fromJSON(rawToChar(base64url_decode(input[1])))
  stopifnot(toupper(header$typ) == "JWT")
  stopifnot(toupper(header$alg) == "HS256")

  # Check integrity
  sig <- base64url_decode(input[3])
  data <- charToRaw(paste(input[1], input[2], sep = "."))
  hmac <- openssl::sha256(data, key = secret)
  if(!identical(sig, unclass(hmac)))
    stop("HMAC signature verification failed!", call. = FALSE)

  # Return payload
  jsonlite::fromJSON(rawToChar(base64url_decode(input[2])))
}

jwt_decode_rs256 <- function(jwt, pubkey){
  # Verify input
  input <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  stopifnot(length(input) == 3)
  header <- jsonlite::fromJSON(rawToChar(base64url_decode(input[1])))
  stopifnot(toupper(header$typ) == "JWT")
  stopifnot(toupper(header$alg) == "RS256")

  # Check integrity
  sig <- base64url_decode(input[3])
  data <- charToRaw(paste(input[1], input[2], sep = "."))
  mypk <- read_pubkey(pubkey)
  if(!signature_verify(data, sig, sha256, pubkey = mypk))
    stop("RSA signature verification failed!", call. = FALSE)

  # Return payload
  jsonlite::fromJSON(rawToChar(base64url_decode(input[2])))
}


#
# jwt_decode_hs256 (
#   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
#   "secret"
# )
#
# pubkeystring = "-----BEGIN PUBLIC KEY-----
# MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
# -----END PUBLIC KEY-----  "
# pk <- read_pubkey(pubkeystring)
# jwt_decode_rs256(
#   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE",
#   pubkey = pk
# )
