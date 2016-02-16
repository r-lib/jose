
#' Generate claim
#'
#' Helper function to create a named list used as the claim of a JWT payload.
#' See \url{https://tools.ietf.org/html/rfc7519#section-4.1} for details.
#'
#' @export
#' @param iss (Issuer) Claim, should be rfc7519 'StringOrURI' value
#' @param sub (Subject) Claim, should be rfc7519 'StringOrURI' value
#' @param aud (Audience) Claim, should contain one or rfc7519 'StringOrURI' values
#' @param exp (Expiration Time) Claim, should be rfc7519 'NumericDate' value
#' @param nbf (Not Before) Claim, should be rfc7519 'NumericDate' value
#' @param iat (Issued At) Claim, should be rfc7519 'NumericDate' value
#' @param jti (JWT ID) Claim, optional unique identifier for the JWT
#' @param ... additional custom claims to include
claim <- function(iss = NULL, sub = NULL, aud = NULL, exp = NULL, nbf = NULL,
                  iat = unclass(Sys.time()), jti = NULL, ...){

  values <- list(
    iss = validate_stringoruri(iss),
    sub = validate_stringoruri(sub),
    aud = validate_stringoruri(aud),
    exp = validate_numericdate(exp),
    nbf = validate_numericdate(nbf),
    iat = validate_numericdate(iat),
    jti = jti,
    ...
  )
  Filter(length, values)
}

validate_stringoruri <- function(str){
  if(is.null(str)) return(NULL)
  if(!is.character(str))
    stop("Invalid 'StringOrURI' value: ", str)
  if(any(grepl(":", str, fixed = TRUE) & !grepl("[a-z]+://", str)))
    stop("Invalid 'StringOrURI' value, the ':' may only appear within a URL")
  str
}

validate_numericdate <- function(val){
  if(is.null(val)) return(NULL)
  max <- unclass(as.POSIXct("2200-01-01"))
  if(!is.numeric(val) || length(val) > 1 || val > max)
    stop("Invalid 'NumericDate' (seconds since epoch) value: ", val)
  round(val)
}
