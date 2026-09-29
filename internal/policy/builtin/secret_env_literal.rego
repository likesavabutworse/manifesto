# METADATA
# title: Credentials are not written into env values
# description: >-
#   An env var named like a password, token or key that carries an inline
#   `value` puts the credential in the chart, in git, and in the Helm release
#   history. Use `valueFrom.secretKeyRef` (or an ExternalSecret). This is a
#   heuristic on the variable's name: names ending in _FILE, _PATH, _NAME or
#   _REF, and values that are a flag (true, false, yes, no, on, off), a number
#   or an absolute path, are skipped: real charts set ALLOW_EMPTY_PASSWORD=no
#   and SECRETS=/run/secrets.
# custom:
#   severity: medium
package manifesto.k8s.secret_env_literal

import data.manifesto.lib

secret_like := `(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)`

not_a_credential := `(?i)_(file|path|name|ref)$`

not_a_secret_value := `(?i)^(true|false|yes|no|on|off|[0-9]+|/.*)$`

deny contains {"msg": msg, "path": "env"} if {
	some c in lib.all_containers
	some e in c.env
	is_string(e.value)
	e.value != ""
	regex.match(secret_like, e.name)
	not regex.match(not_a_credential, e.name)
	not regex.match(not_a_secret_value, e.value)
	msg := sprintf("container %q sets %s to a literal value: use valueFrom.secretKeyRef", [c.name, e.name])
}
