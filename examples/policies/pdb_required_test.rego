package pdb_required_test

import data.pdb_required

deployment(replicas) := {
	"kind": "Deployment",
	"metadata": {"name": "web"},
	"spec": {"replicas": replicas, "template": {"metadata": {"labels": {"app": "web"}}}},
}

pdb(labels) := {"kind": "PodDisruptionBudget", "metadata": {"name": "web"}, "spec": {"selector": {"matchLabels": labels}}}

test_replicated_without_pdb if {
	count(pdb_required.deny) == 1 with input as deployment(3) with data.chart.resources as []
}

test_replicated_with_matching_pdb if {
	count(pdb_required.deny) == 0 with input as deployment(3) with data.chart.resources as [pdb({"app": "web"})]
}

test_pdb_for_other_pods_does_not_count if {
	count(pdb_required.deny) == 1 with input as deployment(3) with data.chart.resources as [pdb({"app": "other"})]
}

test_single_replica_is_exempt if {
	count(pdb_required.deny) == 0 with input as deployment(1) with data.chart.resources as []
}
