package rules

import (
	"fmt"
	"sort"
)

// Scan executes all registered rules applicable to the target in ctx.
// Returns a slice of findings sorted by severity (descending) and source line (ascending).
func Scan(ctx *ScanContext) ([]Finding, error) {
	if ctx == nil {
		return nil, fmt.Errorf("scan context is nil")
	}

	rules := GetRulesForTarget(ctx.TargetType)
	var allFindings []Finding

	for _, rule := range rules {
		findings, err := rule.Evaluate(ctx)
		if err != nil {
			return nil, fmt.Errorf("rule %s (%s) evaluation failed: %w", rule.ID(), rule.Name(), err)
		}
		allFindings = append(allFindings, findings...)
	}

	// Sort findings by severity level descending, then line ascending
	sort.SliceStable(allFindings, func(i, j int) bool {
		lvlI := allFindings[i].Severity.Level()
		lvlJ := allFindings[j].Severity.Level()
		if lvlI != lvlJ {
			return lvlI > lvlJ
		}
		return allFindings[i].Line < allFindings[j].Line
	})

	return allFindings, nil
}
