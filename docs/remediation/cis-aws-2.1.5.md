# All S3 buckets have Public Access Block enabled with every flag on

`CIS-AWS-2.1.5` · framework **cis-aws** · severity **high** · Storage

## What this control checks

CIS AWS Foundations 2.1.5 requires the S3 bucket-level Public Access
Block to be configured with BlockPublicAcls, BlockPublicPolicy,
IgnorePublicAcls, and RestrictPublicBuckets all set to true. This is
the last line of defense against accidentally making a bucket public.

## Why it matters

Even buckets that are correctly configured today drift over time —
a single ACL or bucket-policy mistake can re-expose data. The Public
Access Block flags neutralize public ACLs and policies at the bucket
boundary, so a future misconfiguration cannot leak data without
explicit, deliberate disabling of this control.

## Evidence

Collected from the `aws` source (`s3_public_access_block` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no S3 public-access-block evidence collected
- bucket <value> has no Public Access Block configuration at all
- bucket <value> has Public Access Block flag <value> disabled

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **10m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-2.1.5
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "2.1.5"
  nist_csf:
  - PR.DS-5
  iso27001:
  - A.5.10
  soc2:
  - CC6.6
```
