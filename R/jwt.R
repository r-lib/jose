#' JSON Web Token
#'
#' Sign or verify a JSON web token.
#'
#' @export
#' @rdname jwt_encode
#' @importFrom openssl sha2 signature_create signature_verify read_pubkey read_key
#' @importFrom jsonlite fromJSON toJSON
#' @examples # HMAC signing
#' mysecret <- "This is super secret"
#' token <- list(name = "jeroen", session = 123456)
#' sig <- jwt_encode_hmac(token, mysecret)
#' jwt_decode_hmac(sig, mysecret)
#'
#' # RSA encoding
#' mykey <- openssl::rsa_keygen()
#' pubkey <- as.list(mykey)$pubkey
#' sig <- jwt_encode_rsa(token, mykey)
#' jwt_decode_rsa(sig, pubkey)
#'
#' # Same with EC
#' mykey <- openssl::ec_keygen()
#' pubkey <- as.list(mykey)$pubkey
#' sig <- jwt_encode_ec(token, mykey)
#' jwt_decode_ec(sig, pubkey)
jwt_encode_hmac <- function(payload = list(), secret, size = 256) {
  if(!is.character(secret) && !is.raw(secret))
    stop("Secret must be a string or raw vector")
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
jwt_decode_hmac <- function(jwt, secret){
  if(!is.character(secret) && !is.raw(secret))
    stop("Secret must be a string or raw vector")
  out <- jwt_split(jwt)
  if(out$type != "HMAC")
    stop("Invalid algorithm: ", out$type)
  sig <- sha2(out$data, size = out$keysize, key = secret)
  if(!identical(out$sig, unclass(sig)))
    stop("HMAC signature verification failed!", call. = FALSE)
  return(out$payload)
}

#' @export
#' @rdname jwt_encode
jwt_encode_rsa <- function(payload = list(), key, size = 256) {
  key <- read_key(key)
  if(!inherits(key, "rsa") || !inherits(key, "key"))
    stop("key must be rsa private key")
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("RS", size)
  ))
  doc <- paste(base64url_encode(header), base64url_encode(to_json(payload)), sep = ".")
  dgst <- sha2(charToRaw(doc), size = size)
  sig <- signature_create(dgst, hash = NULL, key = key)
  paste(doc, base64url_encode(sig), sep = ".")
}

#' @export
#' @rdname jwt_encode
jwt_decode_rsa <- function(jwt, pubkey){
  out <- jwt_split(jwt)
  if(out$type != "RSA")
    stop("Invalid algorithm: ", out$type)
  key <- read_pubkey(pubkey)
  if(!inherits(key, "rsa") || !inherits(key, "pubkey"))
    stop("key must be rsa key")
  dgst <- sha2(out$data, size = out$keysize)
  if(!signature_verify(dgst, out$sig, hash = NULL, pubkey = key))
    stop("RSA signature verification failed!", call. = FALSE)
  return(out$payload)
}

#' @export
#' @rdname jwt_encode
jwt_encode_ec <- function(payload = list(), key, size = 256) {
  key <- read_key(key)
  if(!inherits(key, "ecdsa") || !inherits(key, "key"))
    stop("key must be ecdsa private key")
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("ES", size)
  ))
  doc <- paste(base64url_encode(header), base64url_encode(to_json(payload)), sep = ".")
  dgst <- sha2(charToRaw(doc), size = size)
  sig <- signature_create(dgst, hash = NULL, key = key)
  paste(doc, base64url_encode(sig), sep = ".")
}

#' @export
#' @rdname jwt_encode
jwt_decode_ec <- function(jwt, pubkey){
  out <- jwt_split(jwt)
  if(out$type != "ECDSA")
    stop("Invalid algorithm: ", out$type)
  key <- read_pubkey(pubkey)
  if(!inherits(key, "ecdsa") || !inherits(key, "pubkey"))
    stop("key must be ecdsa key")
  dgst <- sha2(out$data, size = out$keysize)
  if(!signature_verify(dgst, out$sig, hash = NULL, pubkey = key))
    stop("RSA signature verification failed!", call. = FALSE)
  return(out$payload)
}

jwt_split <- function(jwt){
  input <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  stopifnot(length(input) == 3)
  header <- jsonlite::fromJSON(rawToChar(base64url_decode(input[1])))
  stopifnot(toupper(header$typ) == "JWT")
  sig <- base64url_decode(input[3])
  header <- fromJSON(rawToChar(base64url_decode(input[1])))
  payload <- fromJSON(rawToChar(base64url_decode(input[2])))
  data <- charToRaw(paste(input[1:2], collapse = "."))
  if(!grepl("^[HRE]S\\d{3}$", header$alg))
    stop("Invalid algorithm: ", header$alg)
  keysize <- as.numeric(substring(header$alg, 3))
  type <- match.arg(substring(header$alg, 1, 1), c("HMAC", "RSA", "ECDSA"))
  list(type = type, keysize = keysize, data = data, sig = sig, payload = payload)
}

to_json <- function(x){
  jsonlite::toJSON(x, auto_unbox = TRUE)
}
