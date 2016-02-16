#' JSON Web Token
#'
#' Sign or verify a JSON web token. The \code{jwt_encode_hmac}, \code{jwt_encode_rsa},
#' and \code{jwt_encode_ec} default to \code{HS256}, \code{RS256}, and \code{ES256}
#' respectively. See \href{https://jwt.io}{jwt.io} or
#' \href{https://tools.ietf.org/html/rfc7519}{RFC7519} for more details.
#'
#' @export
#' @rdname jwt_encode
#' @aliases jwt jose
#' @param claim a named list with fields to include in the jwt payload
#' @param secret string or raw vector with a secret passphrase
#' @param size bitsize of sha2 signature, i.e. \code{sha256}, \code{sha384} or \code{sha512}.
#' @param jwt string containing the JSON Web Token (JWT)
#' @param key path or object with RSA or EC private key, see \link[openssl:read_key]{openssl::read_key}.
#' @param pubkey path or object with RSA or EC public key, see \link[openssl:read_pubkey]{openssl::read_pubkey}.
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
jwt_encode_hmac <- function(claim = new_claim(), secret, size = 256) {
  if(!is.character(secret) && !is.raw(secret))
    stop("Secret must be a string or raw vector")
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("HS", size)
  ))
  body <- to_json(claim)
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
jwt_encode_rsa <- function(claim = new_claim(), key, size = 256) {
  key <- read_key(key)
  if(!inherits(key, "rsa") || !inherits(key, "key"))
    stop("key must be rsa private key")
  if(as.list(key)$size < 2048)
    stop("RSA keysize must be at least 2048 bit")
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("RS", size)
  ))
  doc <- paste(base64url_encode(header), base64url_encode(to_json(claim)), sep = ".")
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
jwt_decode_any <- function(jwt, secret, pubkey){
  out <- jwt_split(jwt)
  if(out$type %in% c("RSA", "ECDSA"))
    pubkey <- read_pubkey(pubkey)
  switch(out$type,
    none = out$payload,
    RSA = jwt_decode_rsa(jwt, pubkey),
    ECDSA = jwt_decode_ec(jwt, pubkey),
    HMAC = jwt_decode_hmac(jwt, secret),
    stop("Invalid type: ", out$type)
  )
}

#' @export
#' @rdname jwt_encode
jwt_encode_ec <- function(claim = new_claim(), key) {
  key <- read_key(key)
  if(!inherits(key, "ecdsa") || !inherits(key, "key"))
    stop("key must be ecdsa private key")
  # See http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.4
  size <- switch(as.list(key)$data$curve,
    "P-256" = 256, "P-384" = 384, "P-521" = 512, stop("invalid curve"))
  header <- to_json(list(
    typ = "JWT",
    alg = paste0("ES", size)
  ))
  doc <- paste(base64url_encode(header), base64url_encode(to_json(claim)), sep = ".")
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
  stopifnot(length(input) %in% c(2,3))
  header <- jsonlite::fromJSON(rawToChar(base64url_decode(input[1])))
  stopifnot(toupper(header$typ) == "JWT")
  if(is.na(input[3])) input[3] = ""
  sig <- base64url_decode(input[3])
  header <- fromJSON(rawToChar(base64url_decode(input[1])))
  payload <- fromJSON(rawToChar(base64url_decode(input[2])))
  data <- charToRaw(paste(input[1:2], collapse = "."))
  if(!grepl("^none|[HRE]S(256|384|512)$", header$alg))
    stop("Invalid algorithm: ", header$alg)
  keysize <- as.numeric(substring(header$alg, 3))
  type <- match.arg(substring(header$alg, 1, 1), c("HMAC", "RSA", "ECDSA"))
  list(type = type, keysize = keysize, data = data, sig = sig, payload = payload)
}

to_json <- function(x){
  jsonlite::toJSON(x, auto_unbox = TRUE)
}
