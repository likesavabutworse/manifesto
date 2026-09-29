package ingress_alb_ssl_policy_test

import data.ingress_alb_ssl_policy

alb(annotations) := {"kind": "Ingress", "metadata": {"name": "web", "annotations": annotations}, "spec": {"ingressClassName": "alb"}}

test_missing_annotation if {
	count(ingress_alb_ssl_policy.deny) == 1 with input as {"kind": "Ingress", "metadata": {"name": "web"}, "spec": {"ingressClassName": "alb"}}
}

test_wrong_policy if {
	count(ingress_alb_ssl_policy.deny) == 1 with input as alb({"alb.ingress.kubernetes.io/ssl-policy": "ELBSecurityPolicy-2016-08"})
}

test_approved_policy if {
	count(ingress_alb_ssl_policy.deny) == 0 with input as alb({"alb.ingress.kubernetes.io/ssl-policy": "ELBSecurityPolicy-TLS-1-1-2017-01"})
}

test_legacy_class_annotation_is_alb if {
	count(ingress_alb_ssl_policy.deny) == 1 with input as {"kind": "Ingress", "metadata": {"name": "web", "annotations": {"kubernetes.io/ingress.class": "alb"}}}
}

test_other_controller_is_ignored if {
	count(ingress_alb_ssl_policy.deny) == 0 with input as {"kind": "Ingress", "metadata": {"name": "web"}, "spec": {"ingressClassName": "nginx"}}
}

test_no_class_is_ignored if {
	count(ingress_alb_ssl_policy.deny) == 0 with input as {"kind": "Ingress", "metadata": {"name": "web"}}
}
