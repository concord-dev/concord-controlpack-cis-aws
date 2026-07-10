# At least one CloudTrail trail logs every region with file-integrity validation

`CIS-AWS-3.1` · framework **cis-aws** · severity **critical** · Logging

## What this control checks

CIS AWS Foundations 3.1 requires a CloudTrail trail that captures
management events across every region, is actively logging, and has
log-file integrity validation enabled. Without this, post-incident
investigation in regions you didn't expect to be in use is impossible.

## Why it matters

A single-region trail leaves blind spots: an attacker who creates
resources in a region you don't watch will leave no audit trail.
File-integrity validation ensures the log files haven't been
tampered with after delivery to S3.

## Evidence

Collected from the `aws` source (`cloudtrail_trails` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudTrail evidence collected
- no CloudTrail trails exist in this account
- no CloudTrail trail satisfies multi-region + logging + file-validation simultaneously
- trail <value> is multi-region but logging is currently stopped
- trail <value> logs every region but log-file validation is off

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **20m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-3.1
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "3.1"
  nist_csf:
  - DE.CM-1
  - PR.PT-1
  iso27001:
  - A.8.15
  soc2:
  - CC7.2
  - CC7.3
```
