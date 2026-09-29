# METADATA
# title: ExternalSecrets read from an approved ClusterSecretStore
# description: >-
#   A namespaced SecretStore lets a team point at any backend with its own
#   credentials, outside platform review. Only the stores in `approved` are
#   allowed.
# custom:
#   severity: high
#   kinds: [ExternalSecret]
package externalsecret_store

approved := {"aws-secretsmanager", "vault-prod"}

deny contains {"msg": msg, "path": "spec.secretStoreRef"} if {
	ref := input.spec.secretStoreRef
	ref.kind != "ClusterSecretStore"
	msg := sprintf("secretStoreRef is a %s (%q); use an approved ClusterSecretStore", [ref.kind, ref.name])
}

deny contains {"msg": msg, "path": "spec.secretStoreRef"} if {
	ref := input.spec.secretStoreRef
	ref.kind == "ClusterSecretStore"
	not ref.name in approved
	msg := sprintf("ClusterSecretStore %q is not approved (want one of %v)", [ref.name, sort(approved)])
}

# ExternalSecret defaults secretStoreRef.kind to SecretStore, so an unset kind
# is the namespaced case.
deny contains {"msg": "secretStoreRef.kind is unset, which means a namespaced SecretStore; use an approved ClusterSecretStore", "path": "spec.secretStoreRef"} if {
	not input.spec.secretStoreRef.kind
}
