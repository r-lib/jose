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
#' Only for HMAC/RSA, not applicable for ECDSA keys.
#' @param header named list with additional parameter fields to include in the jwt header as
#' defined in \href{https://tools.ietf.org/html/rfc7515#section-9.1.2}{rfc7515 section 9.1.2}
#' @param jwt string containing the JSON Web Token (JWT)
#' @param key path or object with RSA or EC private key, see \link[openssl:read_key]{openssl::read_key}.
#' @param pubkey path or object with RSA or EC public key, see \link[openssl:read_pubkey]{openssl::read_pubkey}.
#' @importFrom openssl sha2 signature_create signature_verify read_pubkey read_key
#' @importFrom jsonlite fromJSON toJSON
#' @importFrom utils modifyList
#' @examples # HMAC signing
#' mysecret <- "This is super secret"
#' token <- jwt_claim(name = "jeroen", session = 123456)
#' sig <- jwt_encode_hmac(token, mysecret)
#' jwt_decode_hmac(sig, mysecret)
#'
#' # RSA encoding
#' mykey <- openssl::rsa_keygen()
#' pubkey <- as.list(mykey)$pubkey
#' sig <- jwt_encode_sig(token, mykey)
#' jwt_decode_sig(sig, pubkey)
#'
#' # Same with EC
#' mykey <- openssl::ec_keygen()
#' pubkey <- as.list(mykey)$pubkey
#' sig <- jwt_encode_sig(token, mykey)
#' jwt_decode_sig(sig, pubkey)
#'
#' # Get elements of the key
#' mysecret <- "This is super secret"
#' token <- jwt_claim(name = "jeroen", session = 123456)
#' jwt <- jwt_encode_hmac(token, mysecret)
#' jwt_split(jwt)
jwt_encode_hmac <- function(claim = jwt_claim(), secret, size = 256, header = NULL) {
  stopifnot(inherits(claim, "jwt_claim"))
  if(is.character(secret))
    secret <- charToRaw(secret)
  if(!is.raw(secret))
    stop("Secret must be a string or raw vector")
  if(inherits(secret, "rsa") || inherits(secret, "dsa") || inherits(secret, "ecdsa"))
    stop("Secret must be raw bytes, not a: ", class(secret)[-1])
  jwt_header <- to_json(c(list(
      typ = "JWT",
      alg = paste0("HS", size)
    ), header))
  body <- to_json(claim)
  doc <- paste(base64url_encode(jwt_header), base64url_encode(body), sep = ".")
  sig <- sha2(charToRaw(doc), size = size, key = secret)
  paste(doc, base64url_encode(sig), sep = ".")
}

#' @export
#' @rdname jwt_encode
jwt_decode_hmac <- function(jwt, secret){
  if(is.character(secret))
    secret <- charToRaw(secret)
  if(!is.raw(secret))
    stop("Secret must be a string or raw vector")
  if(inherits(secret, "rsa") || inherits(secret, "dsa") || inherits(secret, "ecdsa"))
    stop("Secret must be raw bytes, not a: ", class(secret)[-1])
  out <- jwt_split(jwt)
  if(out$type != "HMAC")
    stop("Invalid algorithm: ", out$type)
  sig <- sha2(out$data, size = out$keysize, key = secret)
  if(!identical(out$sig, unclass(sig)))
    stop("HMAC signature verification failed!", call. = FALSE)
  structure(out$payload, class = c("jwt_claim", "list"))
}

#' @export
#' @rdname jwt_encode
jwt_encode_sig <- function(claim = jwt_claim(), key, size = 256, header = list()) {
  stopifnot(inherits(claim, "jwt_claim"))
  key <- read_key(key)
  if(!inherits(key, "key"))
    stop("key must be rsa/ecdsa private key")
  # See http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.4
  jwt_header <- if(inherits(key, "rsa")){
  if(as.list(key)$size < 2048)
    stop("RSA keysize must be at least 2048 bit")
    to_json(modifyList(list(
      typ = "JWT",
      alg = paste0("RS", size)
    ), header))
  } else if(inherits(key, "ecdsa")){
    # See http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.4
    size <- switch(as.list(key)$data$curve,
      "P-256" = 256, "P-384" = 384, "P-521" = 512, stop("invalid curve"))
    to_json(modifyList(list(
      typ = "JWT",
      alg = paste0("ES", size)
    ), header))
  } else {
    stop("Key must be RSA or ECDSA private key")
  }
  doc <- paste(base64url_encode(jwt_header), base64url_encode(to_json(claim)), sep = ".")
  dgst <- sha2(charToRaw(doc), size = size)
  sig <- signature_create(dgst, hash = NULL, key = key)
  if(inherits(key, "ecdsa")){
    params <- openssl::ecdsa_parse(sig)
    bitsize <- ceiling(size / 8)
    sig <- c(pad_bignum(params$r, size), pad_bignum(params$s, size))
  }
  paste(doc, base64url_encode(sig), sep = ".")
}

#' @export
#' @rdname jwt_encode
jwt_decode_sig <- function(jwt, pubkey){
  out <- jwt_split(jwt)
  if(out$type != "RSA" && out$type != "ECDSA")
    stop("Invalid algorithm: ", out$type)
  key <- read_pubkey(pubkey)
  if((!inherits(key, "rsa") && !inherits(key, "ecdsa")) || !inherits(key, "pubkey"))
    stop("Key must be rsa/ecdsa public key")
  dgst <- sha2(out$data, size = out$keysize)
  if(out$type == "ECDSA"){
    bitsize <- length(out$sig)/2
    r <- out$sig[seq_len(bitsize)]
    s <- out$sig[seq_len(bitsize) + bitsize]
    out$sig <- openssl::ecdsa_write(r, s)
  }
  if(!signature_verify(dgst, out$sig, hash = NULL, pubkey = key))
    stop(out$type, " signature verification failed!", call. = FALSE)
  structure(out$payload, class = c("jwt_claim", "list"))
}

#' @export
#' @rdname jwt_encode
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

# Adds leading zeros if needed (P512 is 521 bit == 66 bytes)
# Spec: https://tools.ietf.org/html/rfc7518#page-10
pad_bignum <- function(x, keysize){
  stopifnot(keysize %in% c(256, 384, 512))
  bitsize <- switch (as.character(keysize), "256" = 32, "384" = 48, "512" = 66)
  c(raw(bitsize - length(x)), x)
}
