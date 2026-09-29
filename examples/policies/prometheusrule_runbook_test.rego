package prometheusrule_runbook_test

import data.prometheusrule_runbook

rule(r) := {"kind": "PrometheusRule", "metadata": {"name": "app"}, "spec": {"groups": [{"name": "app", "rules": [r]}]}}

test_alert_without_runbook if {
	vs := prometheusrule_runbook.deny with input as rule({"alert": "HighErrorRate", "expr": "up == 0"})
	count(vs) == 1
	some v in vs
	v.path == "spec.groups[0].rules[0]"
}

test_alert_with_empty_runbook if {
	count(prometheusrule_runbook.deny) == 1 with input as rule({"alert": "A", "expr": "up == 0", "annotations": {"runbook_url": ""}})
}

test_alert_with_runbook if {
	count(prometheusrule_runbook.deny) == 0 with input as rule({
		"alert": "A", "expr": "up == 0",
		"annotations": {"runbook_url": "https://runbooks.example.com/a"},
	})
}

test_recording_rule_is_exempt if {
	count(prometheusrule_runbook.deny) == 0 with input as rule({"record": "job:up:sum", "expr": "sum(up)"})
}
