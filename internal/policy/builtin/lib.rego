# Helpers every policy can use via `import data.manifesto.lib`.
#
# They exist so a policy author never has to know that a CronJob's pod spec
# lives four levels deeper than a Deployment's: `lib.containers` works the
# same on every pod-bearing kind and is simply empty on everything else.
package manifesto.lib

pod_template_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job"}

# pod_spec is the PodSpec of the current resource; undefined for kinds that
# don't run pods.
pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in pod_template_kinds

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

# containers are the app containers (spec.containers).
containers := [c | some c in pod_spec.containers]

# init_containers are spec.initContainers.
init_containers := [c | some c in pod_spec.initContainers]

# all_containers is containers + init_containers.
all_containers := array.concat(containers, init_containers)

# name is "Kind/name", for messages.
name := sprintf("%s/%s", [input.kind, input.metadata.name])

# has_label / has_annotation are true when the key is present, even if its
# value is empty.
has_label(key) if _ = input.metadata.labels[key]

has_annotation(key) if _ = input.metadata.annotations[key]
