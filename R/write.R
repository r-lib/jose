#' JSON web-keys
#'
#' Read and write RSA, ECDSA or AES keys as JSON web keys.
#'
#' @export
#' @rdname jwk
#' @name jwk
#' @aliases jwk_write
#' @param x an RSA or EC key or pubkey file
#' @param path file path to write output
#' @examples # generate an ecdsa key
#' library(openssl)
#' key <- ec_keygen("P-521")
#' write_jwk(key)
#' write_jwk(as.list(key)$pubkey)
#'
#' # Same for RSA
#' key <- rsa_keygen()
#' write_jwk(key)
#' write_jwk(as.list(key)$pubkey)
write_jwk <- function(x, path = NULL){
  str <- jwk_export(x)
  if(is.null(path)) return(str)
  writeLines(str, path)
  invisible(path)
}

# Old name
#' @export
jwk_write <- write_jwk

jwk_export <- function(x, ...){
  UseMethod("jwk_export")
}

jwk_export.dsa <- function(x, ...){
  stop("JWK does not support DSA keys. Try RSA or ECDSA instead")
}

jwk_export.ecdsa <- function(x, ...){
  keydata <- as.list(x)$data
  out <- list (
    kty = "EC",
    crv = keydata$curve,
    x = base64url_encode(keydata$x),
    y = base64url_encode(keydata$y)
  )
  if(length(keydata$secret))
    out$d <- base64url_encode(keydata$secret)
  to_json(out)
}

jwk_export.rsa <- function(x, ...){
  keydata <- as.list(x)$data
  out <- lapply(keydata, base64url_encode)
  out$kty <- "RSA"
  to_json(out)
}

jwk_export.raw <- function(x, ...){
  if(is.na(match(length(x), c(16, 24, 32, 48, 64))))
    stop("Raw key must length 16, 24, 32 (AES) or 32, 48, 64 (HMAC)")
  to_json(list(
    kty = "oct",
    k = base64url_encode(x)
  ))
}
