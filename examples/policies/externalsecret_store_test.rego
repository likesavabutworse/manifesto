package externalsecret_store_test

import data.externalsecret_store

es(ref) := {"kind": "ExternalSecret", "metadata": {"name": "db"}, "spec": {"secretStoreRef": ref}}

test_approved_cluster_store if {
	count(externalsecret_store.deny) == 0 with input as es({"kind": "ClusterSecretStore", "name": "vault-prod"})
}

test_unapproved_cluster_store if {
	count(externalsecret_store.deny) == 1 with input as es({"kind": "ClusterSecretStore", "name": "my-own"})
}

test_namespaced_store if {
	count(externalsecret_store.deny) == 1 with input as es({"kind": "SecretStore", "name": "vault-prod"})
}

test_unset_kind_is_namespaced if {
	count(externalsecret_store.deny) == 1 with input as es({"name": "vault-prod"})
}
