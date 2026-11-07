# Public synthetic Roles Anywhere fixtures

`ca.crt` and `other-ca.crt` are synthetic public EC CA certificates with the same subject and different keys. `crls.json` contains base64 DER CRLs signed solely for offline contract tests. Serial 1234 is a synthetic revoked certificate identifier, not an operational certificate. Dates are deliberately fixed for deterministic clock tests.

Fixture signing keys were generated in memory and discarded without serialization. No private key, operational leaf, production CA or AWS readback is stored here. Tests construct synthetic API envelopes explicitly; they cannot prove live AWS behavior.
