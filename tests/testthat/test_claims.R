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

test_that("ValidateDuration", {
  claim <- jwt_claim()
  now <- jwt_claim()$iat
  lifetime <- 1
  future <- ceiling(now + lifetime)
  far_future <- ceiling(future + 5)
  expect_is(claim$exp, "NULL")
  expect_is(validate_duration(claim$exp, now, duration = NULL), "NULL")
  expect_equal(validate_duration(future, now, duration = NULL), future)
  expect_equal(validate_duration(future, now, duration = lifetime), future)
  expect_error(
      validate_duration(far_future, now, duration = lifetime),
      "Expiration time over duration limit"
  )
  Sys.sleep(2)
  expect_error(
      validate_duration(future, now, duration = lifetime),
      "Expiration time exceeded"
  )
})
