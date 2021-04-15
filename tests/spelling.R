if (!requireNamespace("spelling", quietly = TRUE)) {
    cat(
        "Not in a spelling test environment, thats it..",
        file = stderr(),
        fill = TRUE
    )
} else {
    spelling::spell_check_test(vignettes = TRUE, error = FALSE)
}
