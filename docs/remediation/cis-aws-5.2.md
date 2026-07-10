# All VPCs have flow logs enabled

`CIS-AWS-5.2` · framework **cis-aws** · severity **high** · Networking

## What this control checks

CIS AWS Foundations Benchmark 5.2 requires VPC flow logs to be enabled
for every VPC. Flow logs capture the metadata of every IP packet
crossing the VPC's elastic network interfaces — essential for incident
investigation and lateral-movement detection.

## Why it matters

Without flow logs, a post-incident "who talked to whom" question
becomes unanswerable. Enabling flow logs is operationally cheap
(cost scales with traffic, retention configurable) and is the single
most-cited CIS section 5 control during AWS pentests.

## Evidence

Collected from the `aws` source (`vpc_flow_logs` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no VPC evidence collected (AWS collector misconfigured or no credentials)
- VPC <value> has no flow logs configured
- VPC <value> flow logs are configured but not ACTIVE (status=<value>)
- VPC <value> flow logs go to CloudWatch — consider S3 for cheaper long-term retention

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-5.2
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "5.2"
  nist_csf:
  - "DE.AE-3"
  iso27001:
  - "A.8.15"
```
