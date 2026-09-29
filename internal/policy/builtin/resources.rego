# METADATA
# title: Containers set a memory limit and a CPU request
# description: >-
#   Without a memory limit one leaking container can get the whole node
#   OOM-killed; without a CPU request the scheduler packs pods blind.
#   A CPU *limit* is deliberately not required: it causes CFS throttling
#   even on idle nodes, and most platform teams now advise against it.
# custom:
#   severity: medium
package manifesto.k8s.resources

import data.manifesto.lib

deny contains msg if {
	some c in lib.all_containers
	missing := [f | some f in ["resources.limits.memory", "resources.requests.cpu"]; gap(c, f)]
	count(missing) > 0
	msg := sprintf("container %q has no %s", [c.name, concat(" or ", missing)])
}

gap(c, "resources.limits.memory") if not c.resources.limits.memory

# A CPU limit with no request makes Kubernetes default the request to the
# limit, so either one satisfies the scheduler.
gap(c, "resources.requests.cpu") if {
	not c.resources.requests.cpu
	not c.resources.limits.cpu
}
