# Root account has no active access keys

`CIS-AWS-1.4` · framework **cis-aws** · severity **critical** · IAM

## What this control checks

CIS AWS Foundations 1.4 forbids the AWS account root user from
holding active access keys. Root keys grant unrestricted access
to every resource in the account; if leaked they cannot be
revoked without rotating the root credentials themselves.

## Why it matters

Concord checks IAM's account summary for AccountAccessKeysPresent.
Any value greater than zero means the root user has at least one
active access key — a high-impact finding for every cloud audit.

## Evidence

Collected from the `aws` source (`iam_account_summary` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM account summary collected
- root account has <value> active access key(s); rotate to IAM user keys and delete the root keys immediately
- root account MFA is not enabled (covered separately by CIS-AWS-1.5 once implemented)
- only <value> of <value> IAM users have MFA devices configured

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-1.4
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "1.4"
  nist_csf:
  - PR.AC-1
  iso27001:
  - A.5.16
  soc2:
  - CC6.1
  - CC6.2
```
