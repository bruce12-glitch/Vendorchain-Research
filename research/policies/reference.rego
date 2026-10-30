package vendorchain

# New reference policy, not a reconstruction of manuscript Listing 1.
default allow := false

allow if {
    input.format in {"PDF", "PNG", "JPEG"}
    input.documentIntact == true
    input.ocrExpectedMatches == true
    input.sbomValid == true
}
