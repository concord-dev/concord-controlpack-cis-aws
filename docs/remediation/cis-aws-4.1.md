# IAM credentials unused for 90+ days are disabled

`CIS-AWS-4.1` · framework **cis-aws** · severity **high** · IAM

## What this control checks

CIS AWS Foundations 4.1 requires that IAM credentials (console
passwords and access keys) which have been unused for 90 days or
longer be deactivated. Dormant credentials are a common attacker
foothold: they exist long enough to be leaked through Git history,
backups, or developer machines, but nobody notices they're still
valid because no legitimate workflow exercises them.

## Why it matters

Concord parses the IAM credential report (CSV) and flags any user
whose password or access key has not been used in N days (default
90). Tune via concord.yaml:

  spec:
    controls:
      params:
        CIS-AWS-4.1:
          max_unused_days: 60   # tighten for high-trust orgs

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected
- user <value> password active but unused for <value> days (limit <value>) — disable console login
- user <value> access key #<value> active but unused for <value> days (limit <value>) — deactivate the key
- user <value> access key #<value> is active but has never been used — delete it
- user <value> has console login enabled without MFA — covered by CIS-AWS-1.10 if implemented

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework cis-aws --control-id CIS-AWS-4.1
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  cis_aws_v2:
  - "4.1"
  nist_csf:
  - PR.AC-1
  - PR.AC-7
  iso27001:
  - A.5.16
  - A.5.18
  soc2:
  - CC6.2
  - CC6.3
```
