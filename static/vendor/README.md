# Vendored browser cryptography

`forge.min.js` is the unmodified browser distribution of **node-forge 1.4.0**,
downloaded from the official npm package:

- Source: https://registry.npmjs.org/node-forge/-/node-forge-1.4.0.tgz
- Upstream: https://github.com/digitalbazaar/forge/tree/v1.4.0
- Package SHA-256: `bf9d7ca0d774235354697bd4b5e642af6505e7ce2066762c3b855138cf870820`
- Browser bundle SHA-256: `d9b9074e6861200d676e25dcfe97889db5e8f4150bb766d29c491ad709a51b58`
- License: BSD-3-Clause (chosen from upstream's BSD-3-Clause OR GPL-2.0);
  see `node-forge.LICENSE` for the complete upstream license and
  `node-forge.NOTICES` for source notices, including Tom Wu's jsbn license.

The application uses only PEM public-key parsing, UTF-8/Base64 encoding,
SHA-256, and RSA-OAEP public-key encryption. It supplies OAEP's 32-byte seed
directly from browser `crypto.getRandomValues`; failure stops submission.
No third-party CDN is contacted by a visitor.

Security review on 2026-10-14: 1.4.0 is the latest published release. Upstream
issue https://github.com/digitalbazaar/forge/issues/1149 documents
CVE-2026-85393 in RSA PKCS#1 v1.5 **signature verification**, with no published
patched release. Namiya does not call signature verification, certificate-chain
verification, private-key operations, or PKCS#1 v1.5 encryption. The affected
verification path is therefore not reachable through this password envelope.
Recheck this advisory when updating the bundle; do not reuse it for signatures.

This protects password values from passive observation of the form POST. It
does not authenticate scripts or public keys delivered over HTTP. An active
network attacker can replace either, and session cookies and other form fields
still lack transport protection. HTTPS remains a required deployment follow-up.
