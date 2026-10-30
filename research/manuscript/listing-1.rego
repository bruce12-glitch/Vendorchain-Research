package vendorchain.authorization

import future.keywords.in

default allow = false

allow {
    # R1: signed inventory present
    input.sbom.present
    # R2: signature verifies
    input.provenance.signature_valid
    # R3: certificate approved and not expired
    input.provenance.certificate_approved
    not input.provenance.certificate_expired
    # R4: identity state verified
    input.identity.state == "verified"
    # R5: at least one component
    input.sbom.component_count >= 1
    # R6: component count within ceiling
    maxc := input.policy.max_components
    input.sbom.component_count <= maxc
    # R7: no banned package
    not banned_package
    # R8: valid CycloneDX schema
    input.sbom.schema == "cyclonedx"
    # R9: artifact digest bound
    input.provenance.artifact_digest_bound
    # R10: not a detected replay
    not input.replay.detected
}

banned_package {
    some c in input.sbom.components
    c.name in input.policy.banned_packages
}

