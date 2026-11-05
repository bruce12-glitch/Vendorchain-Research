# Identity custody role. Provision decision and policy tokens separately.
path "transit/keys/vendorchain-identity" { capabilities = ["read"] }
path "transit/sign/vendorchain-identity" { capabilities = ["update"] }
