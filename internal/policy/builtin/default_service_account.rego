# METADATA
# title: Pods run as a dedicated ServiceAccount, not "default"
# description: >-
#   A pod that names no serviceAccountName gets the namespace's `default`
#   ServiceAccount, which silently collects every permission anyone later binds
#   to it. A ServiceAccount per workload keeps permissions traceable.
# custom:
#   severity: medium
package manifesto.k8s.default_service_account

import data.manifesto.lib

deny contains {"msg": msg, "path": "serviceAccountName"} if {
	spec := lib.pod_spec
	account(spec) == "default"
	msg := sprintf("%s runs as the \"default\" ServiceAccount: set serviceAccountName to a dedicated one", [lib.name])
}

# serviceAccount is the deprecated spelling of serviceAccountName. A template
# such as `serviceAccountName: {{ .Values.sa }}` with no value renders a null,
# which means "default" just like a missing key.
account(spec) := name if {
	name := spec.serviceAccountName
	is_string(name)
	name != ""
} else := name if {
	name := spec.serviceAccount
	is_string(name)
	name != ""
} else := "default"
