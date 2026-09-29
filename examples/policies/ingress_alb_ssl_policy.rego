# METADATA
# title: ALB Ingresses use the approved TLS policy
# description: >-
#   Our security baseline fixes the TLS policy on every AWS load balancer.
#   Edit `required` when the baseline moves; every chart is then checked
#   against it. Ingresses served by other controllers are left alone.
# custom:
#   severity: high
#   kinds: [Ingress]
package ingress_alb_ssl_policy

import data.manifesto.lib

annotation := "alb.ingress.kubernetes.io/ssl-policy"

required := "ELBSecurityPolicy-TLS-1-1-2017-01"

# The AWS Load Balancer Controller claims an Ingress through
# spec.ingressClassName, or through the legacy kubernetes.io/ingress.class
# annotation that older charts still set. The class is named "alb" by
# default; change it if your cluster's IngressClass has another name.
alb_class := "alb"

is_alb if input.spec.ingressClassName == alb_class

is_alb if input.metadata.annotations["kubernetes.io/ingress.class"] == alb_class

deny contains msg if {
	is_alb
	not lib.has_annotation(annotation)
	msg := sprintf("%s is missing the %s annotation (want %q)", [lib.name, annotation, required])
}

deny contains msg if {
	is_alb
	lib.has_annotation(annotation)
	input.metadata.annotations[annotation] != required
	msg := sprintf("%s sets %s to %q, want %q", [lib.name, annotation, input.metadata.annotations[annotation], required])
}
