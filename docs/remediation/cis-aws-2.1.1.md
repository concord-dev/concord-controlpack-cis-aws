# All S3 buckets have server-side encryption enabled

`CIS-AWS-2.1.1` · framework **cis-aws** · severity **high** · Storage

## What this control checks

CIS AWS Foundations Benchmark 2.1.1 requires server-side encryption
be enabled on every S3 bucket. Concord lists every bucket via the
ListBuckets API, calls GetBucketEncryption on each, and fails the
control if any bucket returns no encryption configuration. Each
rule's algorithm is also surfaced: AES256 raises a warning since
KMS provides stronger key management.

## Why it matters

Without encryption-at-rest a single misconfigured bucket policy
or compromised AWS credential exposes plaintext data. Server-side
encryption is free, transparent to applications, and effectively
mandatory under SOC 2 CC6.7, ISO 27001 A.5.33, and most data
protection regimes.

## Evidence

Collected from the `aws` source (`s3_bucket_encryption` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no S3 evidence collected (AWS collector misconfigured or no credentials)
- bucket <value> has no server-side encryption configured
- bucket <value> uses AES256 (consider aws:kms for stronger key management)
- bucket <value> uses KMS without bucket-key enabled (consider enabling to lower KMS costs)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **15m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-2.1.1
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "2.1.1"
  nist_csf:
  - PR.DS-1
  iso27001:
  - A.5.33
  soc2:
  - CC6.7
```
