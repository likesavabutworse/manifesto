# METADATA
# title: Images are pinned to a version or digest
# description: >-
#   ":latest", a missing tag, or an empty tag (the classic `repo:{{ .Values.tag }}`
#   with tag unset) all mean the image can change under a running release.
# custom:
#   severity: high
package manifesto.k8s.image_tag

import data.manifesto.lib

deny contains msg if {
	some c in lib.all_containers
	not pinned_by_digest(c.image)
	tag(c.image) == "latest"
	msg := sprintf("container %q uses %q: pin a version or digest instead of :latest", [c.name, c.image])
}

deny contains msg if {
	some c in lib.all_containers
	not pinned_by_digest(c.image)
	tag(c.image) == ""
	msg := sprintf("container %q uses %q with an empty tag: is the tag value unset?", [c.name, c.image])
}

deny contains msg if {
	some c in lib.all_containers
	not pinned_by_digest(c.image)
	not tag(c.image)
	msg := sprintf("container %q uses %q with no tag, which means :latest", [c.name, c.image])
}

pinned_by_digest(image) if contains(image, "@")

# The tag lives after the last ":" of the last path segment, so a registry
# port ("localhost:5000/app") isn't mistaken for one.
tag(image) := t if {
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	contains(last, ":")
	t := split(last, ":")[1]
}
