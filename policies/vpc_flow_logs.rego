package concord.cis_aws.vpc_flow_logs

import rego.v1

# CIS AWS Foundations 5.2 — VPC flow logs.
# Adapted from: Prowler `vpc_flow_logs_enabled`, Powerpipe AWS CIS v2 mod
# benchmark `cis_v200_5_2`.
# input.aws_vpcs.vpcs[] each carry `flow_logs: {enabled, status, log_destination_type}`.

deny contains msg if {
    not input.aws_vpcs
    msg := "no VPC evidence collected (AWS collector misconfigured or no credentials)"
}

deny contains msg if {
    some vpc in input.aws_vpcs.vpcs
    not vpc.flow_logs.enabled
    msg := sprintf("VPC %q has no flow logs configured", [vpc.id])
}

deny contains msg if {
    some vpc in input.aws_vpcs.vpcs
    vpc.flow_logs.enabled
    vpc.flow_logs.status != "ACTIVE"
    msg := sprintf("VPC %q flow logs are configured but not ACTIVE (status=%s)", [vpc.id, vpc.flow_logs.status])
}

warn contains msg if {
    some vpc in input.aws_vpcs.vpcs
    vpc.flow_logs.enabled
    vpc.flow_logs.log_destination_type == "cloud-watch-logs"
    msg := sprintf("VPC %q flow logs go to CloudWatch — consider S3 for cheaper long-term retention", [vpc.id])
}
