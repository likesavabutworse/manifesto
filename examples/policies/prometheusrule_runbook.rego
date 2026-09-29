# METADATA
# title: Every alert links to a runbook
# description: >-
#   An alert without a runbook_url pages someone who then has to find out what
#   to do at 3am. Recording rules are exempt: they never page.
# custom:
#   severity: high
#   kinds: [PrometheusRule]
package prometheusrule_runbook

deny contains {"msg": msg, "path": path} if {
	some g, group in input.spec.groups
	some r, rule in group.rules
	rule.alert
	not has_runbook(rule)
	path := sprintf("spec.groups[%d].rules[%d]", [g, r])
	msg := sprintf("alert %q in group %q has no annotations.runbook_url", [rule.alert, group.name])
}

# An empty URL is as useless as a missing one.
has_runbook(rule) if startswith(rule.annotations.runbook_url, "http")
