context("Generating JWT claims")

test_that("StringOrURI", {
  expect_is(new_claim(iss = "foo")$iss, "character")
  expect_is(new_claim(sub = "foo")$sub, "character")
  expect_is(new_claim(aud = c("foo", "bar"))$aud, "character")
  expect_is(new_claim(iss = "http://www.google.com")$iss, "character")
  expect_error(new_claim(iss = 123), "Invalid")
  expect_error(new_claim(iss = "bla:bla"), "Invalid")
})

test_that("NumericDate", {
  val <- unclass(Sys.time())
  expect_is(new_claim(exp = val)$exp, "numeric")
  expect_is(new_claim(nbf = val)$nbf, "numeric")
  expect_is(new_claim(iat = val)$iat, "numeric")
  expect_error(new_claim(exp = "foo"), "Invalid")
  expect_error(new_claim(exp = 1e10), "Invalid")
})
