package concord.cis_aws.unauthorized_api_alarm

import rego.v1

# CIS AWS 6.1 — unauthorized-API-call alarm.
# Adapted from: Prowler `cloudwatch_log_metric_filter_unauthorized_api_calls`.
# input.aws_cloudwatch.metric_filters[] each carry filter_pattern, alarms[], topics[].

deny contains msg if {
    not input.aws_cloudwatch
    msg := "no CloudWatch evidence collected"
}

deny contains msg if {
    count([f |
        some f in input.aws_cloudwatch.metric_filters
        matches_unauthorized(f)
    ]) == 0
    msg := "no CloudWatch metric filter matches unauthorized-API-call pattern"
}

deny contains msg if {
    some f in input.aws_cloudwatch.metric_filters
    matches_unauthorized(f)
    count(f.alarms) == 0
    msg := sprintf("metric filter %q has no alarms attached", [f.name])
}

deny contains msg if {
    some f in input.aws_cloudwatch.metric_filters
    matches_unauthorized(f)
    some a in f.alarms
    count(a.subscribed_topics) == 0
    msg := sprintf("alarm %q on filter %q has no SNS subscribers — it will never page", [a.name, f.name])
}

matches_unauthorized(f) if {
    contains(f.filter_pattern, "UnauthorizedOperation")
}

matches_unauthorized(f) if {
    contains(f.filter_pattern, "AccessDenied")
}
