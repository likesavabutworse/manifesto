package argocd_application_test

import data.argocd_application

app(project, revision) := {
	"kind": "Application",
	"metadata": {"name": "web"},
	"spec": {"project": project, "source": {"repoURL": "https://git.example.com/web", "targetRevision": revision}},
}

test_default_project if {
	count(argocd_application.deny) == 1 with input as app("default", "v1.2.0")
}

test_unset_project_is_default if {
	count(argocd_application.deny) == 1 with input as {"kind": "Application", "metadata": {"name": "web"}, "spec": {"source": {"repoURL": "r", "targetRevision": "v1"}}}
}

test_head_revision if {
	count(argocd_application.deny) == 1 with input as app("payments", "HEAD")
}

test_missing_revision_is_head if {
	count(argocd_application.deny) == 1 with input as {"kind": "Application", "metadata": {"name": "web"}, "spec": {"project": "payments", "source": {"repoURL": "r"}}}
}

test_multiple_sources_each_checked if {
	count(argocd_application.deny) == 1 with input as {"kind": "Application", "metadata": {"name": "web"}, "spec": {"project": "payments", "sources": [
		{"repoURL": "a", "targetRevision": "v1"},
		{"repoURL": "b", "targetRevision": "HEAD"},
	]}}
}

test_compliant if {
	count(argocd_application.deny) == 0 with input as app("payments", "v1.2.0")
}
