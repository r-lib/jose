#' JSON web-keys
#'
#' Read and write RSA, ECDSA or AES keys as JSON web keys.
#'
#' @export
#' @rdname jwk
#' @name jwk
#' @param x an RSA or EC key or pubkey file
#' @param path file path to write output
#' @examples # generate an ecdsa key
#' library(openssl)
#' key <- ec_keygen("P-521")
#' jwk_write(key)
#' jwk_write(as.list(key)$pubkey)
#'
#' # Same for RSA
#' key <- rsa_keygen()
#' jwk_write(key)
#' jwk_write(as.list(key)$pubkey)
jwk_write <- function(x, path = NULL){
  str <- jwk_export(x)
  if(is.null(path)) return(str)
  writeLines(str, path)
  invisible(path)
}

jwk_export <- function(x, ...){
  UseMethod("jwk_export")
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
  if(is.na(match(length(x), c(16, 24, 32))))
    stop("AES key must be of length 16, 24, 32.")
  to_json(list(
    kty = "oct",
    k = base64url_encode(x)
  ))
}
