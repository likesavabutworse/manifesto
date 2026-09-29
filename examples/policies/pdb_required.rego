# METADATA
# title: Replicated Deployments have a PodDisruptionBudget
# description: >-
#   A cross-resource check: data.chart.resources holds every resource the
#   chart rendered, so a policy can look for a PDB whose selector matches
#   this Deployment's pods.
# custom:
#   severity: medium
#   kinds: [Deployment]
package pdb_required

deny contains {"msg": msg, "path": "spec.replicas"} if {
	object.get(input.spec, "replicas", 1) > 1
	not covered
	msg := sprintf("%d replicas but no PodDisruptionBudget selects its pods, so a node drain can take them all down at once", [input.spec.replicas])
}

covered if {
	some pdb in data.chart.resources
	pdb.kind == "PodDisruptionBudget"
	pod_labels := input.spec.template.metadata.labels
	every k, v in pdb.spec.selector.matchLabels {
		pod_labels[k] == v
	}
}
