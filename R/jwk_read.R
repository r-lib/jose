#' @rdname jwk
#' @param file path to file with key data or literal json string
#' @importFrom jsonlite fromJSON validate
#' @export
jwk_read <- function(file){
  jwk <- if(is.character(file)){
    if(validate(file)){
      fromJSON(file)
    } else {
      fromJSON(openssl:::read_input(file))
    }
  } else {
    file
  }
  if(!is.list(jwk) || !length(jwk$kty))
    stop("File does not have jwk data")
  key <- switch(jwk$kty,
    "EC" = jwk_parse_ec(jwk),
    "RSA" = jwk_parse_rsa(jwk),
    stop("Unknown key type: ", jwk$kty)
  )
  pubkey <- if(inherits(key, "key")){
    openssl:::derive_pubkey(key)
  } else {
    key
  }
  type <- openssl:::pubkey_type(pubkey)
  structure(key, class = c(class(key), type))
}

jwk_parse_ec <- function(input){
  curve <- toupper(input$crv)
  x <- base64url_decode(input$x)
  y <- base64url_decode(input$y)
  if(length(input$d)){
    d <- base64url_decode(input$d)
    key <- openssl:::ecdsa_key_build(x, y, d, curve)
    structure(key, class = "key")
  } else {
    pubkey <- openssl:::ecdsa_pubkey_build(x, y, curve)
    structure(pubkey, class = "pubkey")
  }
}

#' @importFrom openssl bignum
jwk_parse_rsa <- function(input){
  e <- bignum(base64url_decode(input$e))
  n <- bignum(base64url_decode(input$n))
  if(length(input$d)){
    p <- bignum(base64url_decode(input$p))
    q <- bignum(base64url_decode(input$q))
    d <- bignum(base64url_decode(input$d))
    key <- openssl:::rsa_key_build(e, n, p, q, d)
    structure(key, class = "key")
  } else {
    pubkey <- openssl:::rsa_pubkey_build(e, n)
    structure(pubkey, class = "pubkey")
  }
}
