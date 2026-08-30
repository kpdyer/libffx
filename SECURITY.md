# Security Policy

## Supported Versions

`libffx` is distributed on [PyPI](https://pypi.org/project/libffx/). Security
fixes are released against the latest published version; please make sure you
are on the most recent release before reporting an issue.

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately through GitHub's
[private vulnerability reporting](https://github.com/kpdyer/libffx/security/advisories/new):

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Include a description, the affected version(s), and reproduction steps.

You can expect an initial response within a few days. Once an issue is
confirmed, a fix and a coordinated disclosure timeline will be arranged.

## Scope

`libffx` implements format-preserving encryption (NIST SP 800-38G FF1).
Reports that are especially relevant include:

- Cryptographic correctness or weaknesses in the FF1 implementation
- Timing side channels in encryption / decryption
- Memory-safety or input-validation issues reachable from the public API

Note that FFX/FPE has inherent, documented limitations (for example, small
domains leak information). Reports that restate these known properties of the
algorithm are considered out of scope.
