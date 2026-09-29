# METADATA
# title: Workloads carry the labels our cost and ownership dashboards need
# custom:
#   severity: medium
#   kinds: [Deployment, StatefulSet, DaemonSet, CronJob]
package required_labels

import data.manifesto.lib

required := {"app.kubernetes.io/name", "team"}

deny contains msg if {
	some label in required
	not lib.has_label(label)
	msg := sprintf("missing label %q", [label])
}
