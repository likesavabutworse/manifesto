# METADATA
# title: RBAC does not grant wildcard access or cluster-admin
# description: >-
#   A `*` in a rule's verbs or resources grants access to everything now and to
#   whatever is added later, including Secrets. A binding to `cluster-admin`
#   hands out the same power by name. Spell out what the workload needs.
# custom:
#   severity: high
#   kinds: [Role, ClusterRole, RoleBinding, ClusterRoleBinding]
package manifesto.k8s.rbac_wildcard

import data.manifesto.lib

deny contains {"msg": msg, "path": sprintf("rules[%d]", [i])} if {
	input.kind in {"Role", "ClusterRole"}
	some i, rule in input.rules
	"*" in rule.verbs
	msg := sprintf("%s rule %d grants all verbs (\"*\")", [lib.name, i])
}

deny contains {"msg": msg, "path": sprintf("rules[%d]", [i])} if {
	input.kind in {"Role", "ClusterRole"}
	some i, rule in input.rules
	"*" in rule.resources
	msg := sprintf("%s rule %d grants access to all resources (\"*\")", [lib.name, i])
}

deny contains {"msg": msg, "path": "roleRef"} if {
	input.kind in {"RoleBinding", "ClusterRoleBinding"}
	input.roleRef.name == "cluster-admin"
	msg := sprintf("%s binds to cluster-admin", [lib.name])
}
