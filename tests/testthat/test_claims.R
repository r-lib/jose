context("Test JWT claims")

test_that("StringOrURI", {
  expect_is(claim(iss = "foo")$iss, "character")
  expect_is(claim(sub = "foo")$sub, "character")
  expect_is(claim(aud = c("foo", "bar"))$aud, "character")
  expect_is(claim(iss = "http://www.google.com")$iss, "character")
  expect_error(claim(iss = 123), "Invalid")
  expect_error(claim(iss = "bla:bla"), "Invalid")
})

test_that("NumericDate", {
  val <- unclass(Sys.time())
  expect_is(claim(exp = val)$exp, "numeric")
  expect_is(claim(nbf = val)$nbf, "numeric")
  expect_is(claim(iat = val)$iat, "numeric")
  expect_error(claim(exp = "foo"), "Invalid")
  expect_error(claim(exp = 1e10), "Invalid")
})
