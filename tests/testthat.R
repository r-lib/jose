if (!requireNamespace("testthat", quietly = TRUE)) {
    cat(
        "Not in a testing environment, thats it..",
        file = stderr(),
        fill = TRUE
    )
} else {
    library(testthat)
    library(jose)

    test_check("jose", reporter = "progress")
}
