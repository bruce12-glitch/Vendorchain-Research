# Attach to the KEK worker token, not the rotation/administration identity.
path "transit/keys/vendorchain-kek" { capabilities = ["read"] }
path "transit/encrypt/vendorchain-kek" { capabilities = ["update"] }
path "transit/decrypt/vendorchain-kek" { capabilities = ["update"] }
