# Cloud direction

## Recognize

Strong signals include cloud infrastructure wording (AWS, GCP, Azure, S3
buckets, metadata endpoints, serverless, containers, Kubernetes, Docker,
CI/CD, Jenkins, GitLab) or supply-chain wording (dependency confusion,
package registry abuse). Medium signals include cloud metadata, object-storage
URLs, container registries, or infrastructure-as-code artifacts.

Distinguish cloud from web: a cloud target is infrastructure or configuration
oriented even when reached over HTTP; a web target is application logic.
Blockchain targets (Solidity, EVM, contracts, chain IDs) are classified as
`cloud` only when the objective is infrastructure; otherwise use the existing
blockchain guidance inside the challenge threat model.

## First information channels

1. Identify the provider, service type, and authentication boundary.
2. Enumerate public buckets, metadata access, and registry/config exposure.
3. Inspect CI/CD, manifests, and dependency resolution for supply-chain paths.
4. Validate one configuration or privilege hypothesis with a bounded check.

Do not attempt provider-wide enumeration or destructive configuration changes.
