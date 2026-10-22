# Verify a release

Every release has `SHA256SUMS`, a Sigstore signature of it (`SHA256SUMS.sigstore.json`), SBOMs (`bunzzle.spdx.json`, `bunzzle.cdx.json`) and GitHub build provenance. Signatures are keyless: they prove the files were built by this repository's release workflow from the tagged commit.

## Binaries

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/bunzzle/bunzzle/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c SHA256SUMS
```

Or with the GitHub CLI:

```sh
gh attestation verify bunzzle-linux-x64 --repo bunzzle/bunzzle
```

## Container image

```sh
cosign verify ghcr.io/bunzzle/bunzzle:v0.2.0 \
  --certificate-identity-regexp '^https://github.com/bunzzle/bunzzle/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/bunzzle/bunzzle:v0.2.0 --repo bunzzle/bunzzle
```

## What's inside

The SBOMs list every dependency. At runtime that is Bun alone, compiled into the binary: Bunzzle has no runtime dependencies. The image is `debian:bookworm-slim` plus the binary, both pinned by digest.
