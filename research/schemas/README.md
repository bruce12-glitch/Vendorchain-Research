The three unchanged JSON schemas and LICENSE are vendored from the CycloneDX
specification, commit `c320fc0f0b46873864927d9d5684eea7ba439728` (release 1.5):
https://github.com/CycloneDX/specification/tree/c320fc0f0b46873864927d9d5684eea7ba439728/schema

`vendorchain.sbom_schema` resolves their references entirely offline. Hardened
Syft runs explicitly emit `cyclonedx-json@1.5`; an unreviewed newer schema version
fails closed. This validates inventory syntax, not completeness or semantic truth.
