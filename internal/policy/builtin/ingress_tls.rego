# METADATA
# title: Ingresses terminate TLS
# description: >-
#   An Ingress with no `spec.tls` serves plain HTTP, unless the controller gets
#   its certificate some other way. Those ways are exempt: an ACM certificate on
#   the AWS Load Balancer Controller, and Google-managed or pre-shared
#   certificates on GKE.
# custom:
#   severity: medium
#   kinds: [Ingress]
package manifesto.k8s.ingress_tls

import data.manifesto.lib

certificate_annotations := {
	"alb.ingress.kubernetes.io/certificate-arn",
	"networking.gke.io/managed-certificates",
	"ingress.gcp.kubernetes.io/pre-shared-cert",
}

deny contains {"msg": msg, "path": "spec.tls"} if {
	count(object.get(input.spec, "tls", [])) == 0
	not has_certificate_annotation
	msg := sprintf("%s has no spec.tls, so it serves plain HTTP", [lib.name])
}

has_certificate_annotation if {
	some a in certificate_annotations
	lib.has_annotation(a)
}
