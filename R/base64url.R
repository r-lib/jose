#' Base64URL encoding
#'
#' The \code{base64url_encode} functions are specified in Section 5 of RFC 4648
#' as a URL-safe alternative to the standard base64. They use different symbols
#' for the 62:nd and 63:rd alphabet character and don't include trailing \code{==}
#' padding.
#'
#' @rdname base64url_encode
#' @importFrom openssl base64_encode
#' @export
base64url_encode <- function(bin){
  text <- base64_encode(bin)
  sub("=+$", "", chartr('+/', '-_', text))
}

#' @rdname base64url_encode
#' @importFrom openssl base64_decode
#' @export
base64url_decode <- function(text){
  text <- fix_padding(chartr('-_', '+/', text))
  base64_decode(text)
}

# Ensures base64 length is a multiple of 4
fix_padding <- function(text){
  text <- gsub("[\r\n]", "", text)[[1]]
  mod <- nchar(text) %% 4;
  if(mod > 0){
    padding <- paste(rep("=", (4 - mod)), collapse = "")
    text <- paste0(text, padding)
  }
  text
}
