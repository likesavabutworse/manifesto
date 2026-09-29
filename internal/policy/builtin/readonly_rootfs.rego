# METADATA
# title: Containers use a read-only root filesystem
# description: >-
#   A writable root filesystem lets an attacker who gets code execution drop
#   tools and persist changes. Mount an emptyDir where the app needs to write.
#   The Pod Security Standards do not require this, even at `restricted`.
# custom:
#   severity: low
package manifesto.k8s.readonly_rootfs

import data.manifesto.lib

deny contains msg if {
	some c in lib.all_containers
	not is_readonly(c)
	msg := sprintf("container %q does not set securityContext.readOnlyRootFilesystem: true", [c.name])
}

is_readonly(c) if c.securityContext.readOnlyRootFilesystem == true
