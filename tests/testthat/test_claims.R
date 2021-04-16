context("Generating JWT claims")

test_that("StringOrURI", {
  expect_is(jwt_claim(iss = "foo")$iss, "character")
  expect_is(jwt_claim(sub = "foo")$sub, "character")
  expect_is(jwt_claim(aud = c("foo", "bar"))$aud, "character")
  expect_is(jwt_claim(iss = "http://www.google.com")$iss, "character")
  expect_error(jwt_claim(iss = 123), "Invalid")
  expect_error(jwt_claim(iss = "bla:bla"), "Invalid")
})

test_that("NumericDate", {
  val <- unclass(Sys.time())
  expect_is(jwt_claim(exp = val)$exp, "numeric")
  expect_is(jwt_claim(nbf = val)$nbf, "numeric")
  expect_is(jwt_claim(iat = val)$iat, "numeric")
  expect_error(jwt_claim(exp = "foo"), "Invalid")
  expect_error(jwt_claim(exp = 1e10), "Invalid")
})

test_that("ValidateExp", {
  claim <- jwt_claim()
  val <- jwt_claim()$iat
  lifetime <- 1
  future <- ceiling(val + lifetime)
  far_future <- ceiling(val + lifetime + 5)
  expect_is(claim$exp, "NULL")
  expect_warning(validate_exp(NULL, exp = NULL), "Not check")
  expect_is(suppressWarnings({validate_exp(claim$exp, exp = NULL)}), "NULL")
  expect_equal(suppressWarnings({validate_exp(future, exp = lifetime)}), future)
  expect_error(
      validate_exp(far_future, exp = lifetime),
      "Expiration time invalid"
  )
  Sys.sleep(2)
  expect_error(
      validate_exp(future, exp = lifetime),
      "Expiration time exceeded"
  )
})
