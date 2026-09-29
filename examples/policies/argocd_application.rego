# METADATA
# title: Argo CD Applications leave the default project and track a pinned revision
# description: >-
#   The `default` project can deploy anything to anywhere, so it defeats the
#   point of AppProjects. A revision of HEAD (or none) deploys whatever was
#   pushed last, with no review of the exact commit.
# custom:
#   severity: high
#   kinds: [Application]
package argocd_application

import data.manifesto.lib

deny contains {"msg": msg, "path": "spec.project"} if {
	object.get(input.spec, "project", "default") == "default"
	msg := sprintf("%s uses the default AppProject; create a project that limits repos and destinations", [lib.name])
}

# spec.source and spec.sources[] both carry a targetRevision.
sources := [input.spec.source] if input.spec.source

sources := input.spec.sources if input.spec.sources

deny contains {"msg": msg, "path": "spec.source"} if {
	some s in sources
	object.get(s, "targetRevision", "HEAD") == "HEAD"
	msg := sprintf("%s tracks HEAD of %s; pin a tag, or a branch you protect", [lib.name, s.repoURL])
}
