#' JSON Web Token
#'
#' Sign or verify a JSON web token
#'
#' @export
#' @rdname jwt_encode
#' @examples # HMAC signing
#' mysecret <- "This is super secret"
#' token <- list(name = "jeroen", session = 123456)
#' jwt_encode_hmac(token, mysecret)
#'
#' # RSA encoding
#' mykey <- openssl::rsa_keygen()
#' jwt_encode_rsa(token, mykey)
#'
#' # Same with EC
#' mykey <- openssl::ec_keygen()
#' jwt_encode_ec(token, mykey)
jwt_encode_hmac <- function(payload = list(), secret = "secret", size = 256) {
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("HS", size)
  ))
  body <- to_json(payload)
  doc <- paste(base64url_encode(header), base64url_encode(body), sep = ".")
  sig <- sha2(charToRaw(doc), size = size, key = secret)
  paste(doc, base64url_encode(sig), sep = ".")
}

#' @export
#' @rdname jwt_encode
jwt_encode_rsa <- function(payload = list(), key, size = 256) {
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("RS", size)
  ))
  stopifnot(inherits(key, "rsa"))
  body <- to_json(payload)
  doc <- paste(base64url_encode(header), base64url_encode(body), sep = ".")
  sig <- signature_create(charToRaw(doc), function(x){sha2(x, size = size)}, key = key)
  paste(doc, base64url_encode(sig), sep = ".")
}

#' @export
#' @rdname jwt_encode
jwt_encode_ec <- function(payload = list(), key = openssl::my_key(), size = 256) {
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("ES", size)
  ))
  stopifnot(inherits(key, "ecdsa"))
  body <- to_json(payload)
  doc <- paste(base64url_encode(header), base64url_encode(body), sep = ".")
  sig <- signature_create(charToRaw(doc), function(x){sha2(x, size = size)}, key = key)
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

to_json <- function(x){
  jsonlite::toJSON(x, auto_unbox = TRUE)
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
