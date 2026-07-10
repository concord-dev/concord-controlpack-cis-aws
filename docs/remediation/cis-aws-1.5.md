# Root account has MFA enabled

`CIS-AWS-1.5` · framework **cis-aws** · severity **critical** · IAM

## What this control checks

CIS AWS Foundations 1.5 requires the root account to have MFA enabled.
The root user holds full account privileges; without MFA, a single
credential leak compromises the entire AWS account.

## Why it matters

Concord checks the IAM account summary for AccountMFAEnabled. A
value of 1 means root MFA is on. We do not require hardware MFA
here (covered separately by CIS-AWS-1.6); any MFA factor satisfies
this baseline check.

## Evidence

Collected from the `aws` source (`iam_account_summary` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM account summary collected
- root account MFA is not enabled — enable an MFA device on the root user immediately
- root account still has signing certificates configured (remove unless required)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **15m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-1.5
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "1.5"
  nist_csf:
  - PR.AC-7
  iso27001:
  - A.5.17
  soc2:
  - CC6.1
```
