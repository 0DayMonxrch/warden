package rules

import (
	"fmt"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Rule)
	order      []string
)

// Register registers a new rule in the central rule registry.
func Register(r Rule) {
	registryMu.Lock()
	defer registryMu.Unlock()

	id := r.ID()
	if _, exists := registry[id]; exists {
		panic(fmt.Sprintf("rule with ID %q already registered", id))
	}

	registry[id] = r
	order = append(order, id)
}

// AllRules returns all registered rules in order of registration.
func AllRules() []Rule {
	registryMu.RLock()
	defer registryMu.RUnlock()

	rules := make([]Rule, 0, len(order))
	for _, id := range order {
		rules = append(rules, registry[id])
	}
	return rules
}

// GetRulesForTarget returns all registered rules that apply to the specified target type.
func GetRulesForTarget(t TargetType) []Rule {
	registryMu.RLock()
	defer registryMu.RUnlock()

	var matched []Rule
	for _, id := range order {
		r := registry[id]
		for _, target := range r.Targets() {
			if target == t {
				matched = append(matched, r)
				break
			}
		}
	}
	return matched
}

// GetRuleByID returns a registered rule by its ID.
func GetRuleByID(id string) (Rule, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	r, exists := registry[id]
	return r, exists
}

// ResetRegistry clears the registry (primarily useful for isolated testing).
func ResetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()

	registry = make(map[string]Rule)
	order = nil
}
