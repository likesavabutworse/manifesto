// Package severity defines the three finding severities shared by every
// policy backend (Rego, CEL, Pod Security Standards, template lint) and by
// reporting, so they stay one set of strings instead of each package
// maintaining its own copy.
package severity

const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Rank orders severities; lower is more severe. Unknown severities rank -1.
func Rank(s string) int {
	switch s {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	}
	return -1
}
