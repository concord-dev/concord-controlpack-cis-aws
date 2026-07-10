# IAM account password policy meets CIS minimums

`CIS-AWS-1.16` · framework **cis-aws** · severity **high** · IAM

## What this control checks

CIS AWS Foundations 1.16 requires the account's IAM password policy to
enforce length, complexity, rotation, and reuse-prevention minimums.
A weak or unset password policy lets human users register guessable
credentials that ride alongside production access.

## Why it matters

Concord pulls the live policy via iam:GetAccountPasswordPolicy. A
missing policy (NoSuchEntity) is a hard fail. Configured policies are
measured against the CIS thresholds; each unmet threshold becomes a
distinct deny message so the user fixes the exact field that's wrong.

## Evidence

Collected from the `aws` source (`iam_password_policy` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM password policy evidence collected
- no IAM account password policy is configured (CIS-AWS-1.16 requires one)
- minimum_password_length is <value>, must be >= <value>
- require_symbols is false (CIS-AWS-1.16 requires symbols)
- require_numbers is false (CIS-AWS-1.16 requires digits)
- require_uppercase_characters is false (CIS-AWS-1.16 requires uppercase)
- require_lowercase_characters is false (CIS-AWS-1.16 requires lowercase)
- expire_passwords is false; max_password_age must be set to <= <value> days
- max_password_age is <value>, must be <= <value> days
- password_reuse_prevention is <value>, must remember >= <value> previous passwords
- users cannot change their own passwords — required for rotation hygiene

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **15m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-1.16
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "1.16"
  nist_csf:
  - PR.AC-1
  iso27001:
  - A.5.17
  soc2:
  - CC6.1
```
