# CloudWatch alarm fires on unauthorized API calls

`CIS-AWS-6.1` · framework **cis-aws** · severity **high** · Monitoring

## What this control checks

CIS AWS Foundations Benchmark 6.1 requires a CloudWatch metric filter +
alarm that fires on unauthorised API calls (errorCode containing
"*UnauthorizedOperation" or "AccessDenied"). The alarm must publish
to an SNS topic with at least one subscriber so it actually pages.

## Why it matters

Unauthorised API calls are the highest-confidence signal of credential
compromise or lateral movement attempts. CIS 6.1 is the canonical
"credential abuse" control auditors look for during AWS reviews.

## Evidence

Collected from the `aws` source (`metric_filter_alarms` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudWatch evidence collected
- no CloudWatch metric filter matches unauthorized-API-call pattern
- metric filter <value> has no alarms attached
- alarm <value> on filter <value> has no SNS subscribers — it will never page

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-6.1
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "6.1"
  nist_csf:
  - "DE.CM-7"
  iso27001:
  - "A.8.16"
```
