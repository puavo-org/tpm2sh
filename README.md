# tpm2sh

A command-line interface for TPM 2.0 chips.

Example:

```fish
tpm2sh create-primary --algorithm rsa:2048:sha256 |
tpm2sh seal --object-password "abc" --data data://utf8,my-secret-password |
tpm2sh load --parent-password "" |
tpm2sh unseal --password "abc"
```

## Development

* Commits: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
* New commits should include a `Signed-off-by` trailer.
* Versioning: [Semantic Versioning](https://semver.org/).

