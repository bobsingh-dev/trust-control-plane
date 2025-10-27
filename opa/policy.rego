package trust

# Default deny
default allow := false

# Allow rule — ServiceB can call ServiceA if attested
allow if {
    input.identity == "spiffe://trust.local/serviceB"
    input.attested == true
}
