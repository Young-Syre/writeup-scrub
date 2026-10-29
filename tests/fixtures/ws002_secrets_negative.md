# No live secrets here

Test-mode keys are not live credentials: sk_test_EXAMPLE_NOT_A_REAL_KEY.

A public SSH key is not a private key:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaQmRMUlNQbEtmU3BLZ1pFV3BZZVZpT0lE user@target
```

```
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKS0yiqKk2gUMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMTCWxv
-----END CERTIFICATE-----
```

Words that merely look structured: skipped, skeleton, AKIAI (too short), and
a base64 blob that is not a JWT: YWJjZGVmZ2hpamtsbW5vcA==.
