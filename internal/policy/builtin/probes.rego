# METADATA
# title: Long-running containers define liveness and readiness probes
# description: >-
#   Without a readiness probe a Service routes traffic to pods that haven't
#   finished starting; without a liveness probe a wedged process is never
#   restarted. Jobs and bare Pods are exempt: they are meant to exit.
# custom:
#   severity: medium
#   kinds: [Deployment, StatefulSet, DaemonSet]
package manifesto.k8s.probes

import data.manifesto.lib

deny contains msg if {
	some c in lib.containers
	missing := [p | some p in ["livenessProbe", "readinessProbe"]; not c[p]]
	count(missing) > 0
	msg := sprintf("container %q has no %s", [c.name, concat(" or ", missing)])
}
