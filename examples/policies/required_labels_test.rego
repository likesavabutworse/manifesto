package required_labels_test

import data.required_labels

test_both_missing if {
	count(required_labels.deny) == 2 with input as {"kind": "Deployment", "metadata": {"name": "web"}}
}

test_all_present if {
	count(required_labels.deny) == 0 with input as {"kind": "Deployment", "metadata": {
		"name": "web",
		"labels": {"app.kubernetes.io/name": "web", "team": "payments"},
	}}
}
