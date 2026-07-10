# Every IAM user with a console password has MFA enabled

`CIS-AWS-1.10` · framework **cis-aws** · severity **critical** · IAM

## What this control checks

CIS AWS Foundations 1.10 requires that every IAM user who can log in
to the AWS Console (i.e. has a console password set) also has at
least one MFA device enabled. Password-only access to the console
is one of the highest-impact attack paths in AWS — a leaked password
becomes account takeover.

## Why it matters

Concord parses the IAM credential report. For every user with
password_enabled = true and mfa_active = false, an explicit deny
fires. The root account is excluded because CIS-AWS-1.5 already
covers root MFA separately with stronger remediation guidance.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected
- user <value> has a console password but no MFA device — enroll an MFA factor or disable console login

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-1.10
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "1.10"
  nist_csf:
  - PR.AC-7
  iso27001:
  - A.5.17
  soc2:
  - CC6.1
```
