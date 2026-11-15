#' JSON Web Encryption
#'
#' Encrypt or decrypt data or a JWT claim using JSON Web Encryption (JWE) in compact
#' serialization, see \href{https://datatracker.ietf.org/doc/html/rfc7516}{RFC7516}.
#' The content is encrypted with a random content encryption key (CEK), which is in
#' turn encrypted for the recipient using the key management algorithm \code{alg}.
#'
#' Supported key management algorithms (\code{alg}) are:
#' \itemize{
#'   \item \code{RSA-OAEP} and \code{RSA-OAEP-256}: for an RSA key.
#'   \item \code{ECDH-ES}, \code{ECDH-ES+A128KW}, \code{ECDH-ES+A192KW} and \code{ECDH-ES+A256KW}:
#'   for an EC key (P-256, P-384, or P-521).
#'   \item \code{A128KW}, \code{A192KW} and \code{A256KW}: AES key wrap with a shared secret
#'   (raw vector) of 16, 24 or 32 bytes.
#'   \item \code{dir}: direct encryption with a shared secret (raw vector) that has the
#'   key size of \code{enc}.
#' }
#' If \code{alg} is \code{NULL}, it defaults to \code{RSA-OAEP-256} for RSA keys,
#' \code{ECDH-ES} for EC keys, and the AES key wrap of the matching size for raw keys.
#'
#' Supported content encryption algorithms (\code{enc}) are \code{A128GCM}, \code{A192GCM},
#' \code{A256GCM}, \code{A128CBC-HS256}, \code{A192CBC-HS384} and \code{A256CBC-HS512}.
#'
#' @export
#' @rdname jwe
#' @name jwe
#' @param payload string or raw vector with the data to encrypt
#' @param key for encryption: path or object with the RSA or EC public key of the recipient,
#' or a raw vector with a shared secret. For decryption: path or object with the RSA or EC
#' private key, or a raw vector with the shared secret.
#' @param alg key management algorithm, see details.
#' @param enc content encryption algorithm, see details.
#' @param header named list with additional parameter fields to include in the protected
#' header, for example \code{kid}.
#' @param jwe string containing the JWE in compact serialization
#' @return \code{jwe_encrypt} and \code{jwt_encrypt} return a string with the JWE.
#' \code{jwe_decrypt} returns a raw vector with the decrypted payload, and \code{jwt_decrypt}
#' returns the decrypted claim.
#' @examples # Encrypt with RSA
#' key <- openssl::rsa_keygen()
#' pubkey <- as.list(key)$pubkey
#' token <- jwe_encrypt("Hello world", pubkey)
#' rawToChar(jwe_decrypt(token, key))
#'
#' # Encrypt with EC
#' key <- openssl::ec_keygen()
#' pubkey <- as.list(key)$pubkey
#' token <- jwe_encrypt("Hello world", pubkey, enc = "A128CBC-HS256")
#' rawToChar(jwe_decrypt(token, key))
#'
#' # Encrypt with a shared secret
#' secret <- openssl::rand_bytes(32)
#' token <- jwe_encrypt("Hello world", secret)
#' rawToChar(jwe_decrypt(token, secret))
#'
#' # Encrypt a JWT
#' claim <- jwt_claim(name = "jeroen", session = 123456)
#' token <- jwt_encrypt(claim, pubkey)
#' jwt_decrypt(token, key)
jwe_encrypt <- function(payload, key, alg = NULL, enc = "A256GCM", header = NULL){
  if(is.character(payload))
    payload <- charToRaw(enc2utf8(payload))
  if(!is.raw(payload))
    stop("Payload must be a string or raw vector")
  if(any(c("alg", "enc", "epk") %in% names(header)))
    stop("Use the alg and enc arguments instead of setting these in the header")
  key <- jwe_read_key(key, private = FALSE)
  if(is.null(alg))
    alg <- jwe_default_alg(key)
  keylen <- jwe_enc_keylen(enc)
  km <- jwe_key_encrypt(alg, key, keylen, enc, header)
  jwe_header <- to_json(c(list(alg = alg, enc = enc), km$header, header))
  protected <- base64url_encode(jwe_header)
  content <- jwe_content_encrypt(enc, km$cek, payload, charToRaw(protected))
  paste(protected, base64url_encode(km$encrypted_key), base64url_encode(content$iv),
        base64url_encode(content$ciphertext), base64url_encode(content$tag), sep = ".")
}

#' @export
#' @rdname jwe
jwe_decrypt <- function(jwe, key){
  input <- strsplit(jwe, ".", fixed = TRUE)[[1]]
  if(length(input) == 4 && grepl("\\.$", jwe))
    input <- c(input, "")
  if(length(input) != 5)
    stop("Invalid JWE: compact serialization must have 5 parts")
  header <- fromJSON(rawToChar(base64url_decode(input[1])), simplifyVector = FALSE)
  if(length(header$zip))
    stop("Compressed JWE (zip) is not supported")
  if(length(header$crit))
    stop("Unsupported critical header parameters: ", paste(header$crit, collapse = ", "))
  if(!is.character(header$alg) || !is.character(header$enc))
    stop("JWE header must contain 'alg' and 'enc'")
  key <- jwe_read_key(key, private = TRUE)
  keylen <- jwe_enc_keylen(header$enc)
  cek <- jwe_key_decrypt(header$alg, key, base64url_decode(input[2]), keylen, header)
  if(length(cek) != keylen)
    stop("JWE decryption failed: invalid content encryption key", call. = FALSE)
  jwe_content_decrypt(header$enc, cek, base64url_decode(input[3]), base64url_decode(input[4]),
                      base64url_decode(input[5]), charToRaw(input[1]))
}

#' @export
#' @rdname jwe
#' @param claim a named list with fields to include in the jwt payload, see \link{jwt_claim}
jwt_encrypt <- function(claim = jwt_claim(), key, alg = NULL, enc = "A256GCM", header = NULL){
  stopifnot(inherits(claim, "jwt_claim"))
  header <- utils::modifyList(list(typ = "JWT"), as.list(header))
  jwe_encrypt(to_json(claim), key = key, alg = alg, enc = enc, header = header)
}

#' @export
#' @rdname jwe
#' @param jwt string containing the encrypted JSON Web Token
jwt_decrypt <- function(jwt, key){
  payload <- fromJSON(rawToChar(jwe_decrypt(jwt, key)))
  check_expiration_time(payload)
  structure(payload, class = c("jwt_claim", "list"))
}

jwe_read_key <- function(key, private){
  if(is.raw(key) && !inherits(key, c("key", "pubkey")))
    return(key)
  key <- if(private) read_key(key) else read_pubkey(key)
  if(!inherits(key, c("rsa", "ecdsa")))
    stop("Key must be an RSA or EC key, or a raw vector with a shared secret")
  key
}

jwe_default_alg <- function(key){
  if(inherits(key, "rsa")) return("RSA-OAEP-256")
  if(inherits(key, "ecdsa")) return("ECDH-ES")
  switch(as.character(length(key)), "16" = "A128KW", "24" = "A192KW", "32" = "A256KW",
         stop("Secret must be 16, 24 or 32 bytes for AES key wrap"))
}

jwe_enc_keylen <- function(enc){
  switch(enc, A128GCM = 16, A192GCM = 24, A256GCM = 32, "A128CBC-HS256" = 32,
         "A192CBC-HS384" = 48, "A256CBC-HS512" = 64, stop("Unsupported enc: ", enc))
}

jwe_kw_keylen <- function(alg){
  as.numeric(sub("^(ECDH-ES\\+)?A(128|192|256)KW$", "\\2", alg)) / 8
}

jwe_check_key <- function(alg, key, type){
  ok <- if(type == "raw") is.raw(key) && !inherits(key, c("key", "pubkey")) else inherits(key, type)
  if(!ok)
    stop(sprintf("Algorithm %s requires a %s key", alg, switch(type, raw = "raw (shared secret)", rsa = "RSA", ecdsa = "EC")))
}

jwe_key_encrypt <- function(alg, key, keylen, enc, header){
  if(alg == "dir"){
    jwe_check_key(alg, key, "raw")
    if(length(key) != keylen)
      stop(sprintf("Secret for dir with %s must be %d bytes", enc, keylen))
    return(list(cek = unclass(key), encrypted_key = raw()))
  }
  cek <- openssl::rand_bytes(keylen)
  if(grepl("^A(128|192|256)KW$", alg)){
    jwe_check_key(alg, key, "raw")
    if(length(key) != jwe_kw_keylen(alg))
      stop(sprintf("Secret for %s must be %d bytes", alg, jwe_kw_keylen(alg)))
    list(cek = cek, encrypted_key = openssl::aes_keywrap(cek, unclass(key)))
  } else if(alg %in% c("RSA-OAEP", "RSA-OAEP-256")){
    jwe_check_key(alg, key, "rsa")
    oaep <- if(alg == "RSA-OAEP") TRUE else "sha256"
    list(cek = cek, encrypted_key = openssl::rsa_encrypt(cek, key, oaep = oaep))
  } else if(grepl("^ECDH-ES(\\+A(128|192|256)KW)?$", alg)){
    jwe_check_key(alg, key, "ecdsa")
    curve <- as.list(key)$data$curve
    ephemeral <- openssl::ec_keygen(curve)
    z <- openssl::ec_dh(ephemeral, key)
    epk <- jwe_epk(as.list(ephemeral)$pubkey)
    apu <- jwe_header_bytes(header$apu)
    apv <- jwe_header_bytes(header$apv)
    if(alg == "ECDH-ES"){
      cek <- concat_kdf(z, keylen, enc, apu, apv)
      list(cek = cek, encrypted_key = raw(), header = list(epk = epk))
    } else {
      kek <- concat_kdf(z, jwe_kw_keylen(alg), alg, apu, apv)
      list(cek = cek, encrypted_key = openssl::aes_keywrap(cek, kek), header = list(epk = epk))
    }
  } else {
    stop("Unsupported alg: ", alg)
  }
}

jwe_key_decrypt <- function(alg, key, encrypted_key, keylen, header){
  if(alg == "dir"){
    jwe_check_key(alg, key, "raw")
    if(length(encrypted_key))
      stop("JWE with alg dir must not have an encrypted key")
    unclass(key)
  } else if(grepl("^A(128|192|256)KW$", alg)){
    jwe_check_key(alg, key, "raw")
    if(length(key) != jwe_kw_keylen(alg))
      stop(sprintf("Secret for %s must be %d bytes", alg, jwe_kw_keylen(alg)))
    jwe_try(openssl::aes_keyunwrap(encrypted_key, unclass(key)))
  } else if(alg %in% c("RSA-OAEP", "RSA-OAEP-256")){
    jwe_check_key(alg, key, "rsa")
    oaep <- if(alg == "RSA-OAEP") TRUE else "sha256"
    jwe_try(openssl::rsa_decrypt(encrypted_key, key, oaep = oaep))
  } else if(grepl("^ECDH-ES(\\+A(128|192|256)KW)?$", alg)){
    jwe_check_key(alg, key, "ecdsa")
    if(!is.list(header$epk) || !identical(header$epk$kty, "EC"))
      stop("JWE header must contain an EC 'epk'")
    if(!identical(header$epk$crv, as.list(key)$data$curve))
      stop("Curve of 'epk' does not match the key")
    epk <- read_jwk(header$epk)
    z <- openssl::ec_dh(key, epk)
    apu <- jwe_header_bytes(header$apu)
    apv <- jwe_header_bytes(header$apv)
    if(alg == "ECDH-ES"){
      if(length(encrypted_key))
        stop("JWE with alg ECDH-ES must not have an encrypted key")
      concat_kdf(z, keylen, header$enc, apu, apv)
    } else {
      kek <- concat_kdf(z, jwe_kw_keylen(alg), alg, apu, apv)
      jwe_try(openssl::aes_keyunwrap(encrypted_key, kek))
    }
  } else {
    stop("Unsupported alg: ", alg)
  }
}

jwe_content_encrypt <- function(enc, cek, plaintext, aad){
  if(grepl("GCM$", enc)){
    iv <- openssl::rand_bytes(12)
    ct <- openssl::aes_gcm_encrypt(plaintext, cek, iv = iv, aad = aad)
    list(iv = iv, ciphertext = as.vector(ct), tag = attr(ct, "tag"))
  } else {
    n <- length(cek) / 2
    iv <- openssl::rand_bytes(16)
    ct <- as.vector(openssl::aes_cbc_encrypt(plaintext, cek[n + seq_len(n)], iv = iv))
    list(iv = iv, ciphertext = ct, tag = cbc_hmac_tag(cek[seq_len(n)], aad, iv, ct))
  }
}

jwe_content_decrypt <- function(enc, cek, iv, ciphertext, tag, aad){
  if(grepl("GCM$", enc)){
    if(length(tag) != 16 || length(iv) != 12)
      stop("JWE decryption failed: invalid iv or tag", call. = FALSE)
    jwe_try(openssl::aes_gcm_decrypt(ciphertext, cek, iv = iv, tag = tag, aad = aad))
  } else {
    n <- length(cek) / 2
    if(length(iv) != 16 || !identical(tag, cbc_hmac_tag(cek[seq_len(n)], aad, iv, ciphertext)))
      stop("JWE decryption failed: authentication tag mismatch", call. = FALSE)
    jwe_try(openssl::aes_cbc_decrypt(ciphertext, cek[n + seq_len(n)], iv = iv))
  }
}

# RFC 7518 section 5.2.2.1
cbc_hmac_tag <- function(mac_key, aad, iv, ciphertext){
  al <- uint_bytes(length(aad) * 8, 8)
  mac <- sha2(c(aad, iv, ciphertext, al), size = length(mac_key) * 16, key = mac_key)
  unclass(mac)[seq_len(length(mac_key))]
}

# Concat KDF from NIST SP 800-56A, see RFC 7518 section 4.6.2
concat_kdf <- function(z, keylen, algid, apu = raw(), apv = raw()){
  with_length <- function(x) c(uint_bytes(length(x), 4), x)
  otherinfo <- c(with_length(charToRaw(algid)), with_length(apu), with_length(apv),
                 uint_bytes(keylen * 8, 4))
  rounds <- lapply(seq_len(ceiling(keylen / 32)), function(i){
    unclass(openssl::sha256(c(uint_bytes(i, 4), z, otherinfo)))
  })
  unlist(rounds)[seq_len(keylen)]
}

uint_bytes <- function(x, n){
  as.raw(floor(x / 256^((n - 1):0)) %% 256)
}

jwe_header_bytes <- function(x){
  if(length(x)) base64url_decode(x) else raw()
}

jwe_epk <- function(pubkey){
  data <- as.list(pubkey)$data
  size <- switch(data$curve, "P-256" = 256, "P-384" = 384, "P-521" = 512, stop("Unsupported curve: ", data$curve))
  list(
    kty = "EC",
    crv = data$curve,
    x = base64url_encode(pad_bignum(data$x, size)),
    y = base64url_encode(pad_bignum(data$y, size))
  )
}

jwe_try <- function(expr){
  tryCatch(expr, error = function(e){
    stop("JWE decryption failed: wrong key or data has been modified", call. = FALSE)
  })
}
