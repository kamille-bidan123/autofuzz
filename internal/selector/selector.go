package selector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type orderSet struct {
	APIs []string `json:"apis"`
}

type candidate struct {
	Functions []string
	Score     int
}

func Select(outputPath string, available []string, maximum int) ([]string, error) {
	availableSet := make(map[string]bool, len(available))
	for _, name := range available {
		availableSet[name] = true
	}
	orderPath := filepath.Join(outputPath, "preprocessor", "call_order.json")
	if selected := fromOrderSets(orderPath, availableSet, maximum); len(selected) >= 2 {
		return selected, nil
	}
	selected := fromNames(available, maximum)
	if len(selected) < 2 {
		return nil, fmt.Errorf("could not form a lifecycle API group from %d APIs", len(available))
	}
	return selected, nil
}

func fromOrderSets(path string, available map[string]bool, maximum int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]orderSet
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}
	var candidates []candidate
	for _, item := range raw {
		var names []string
		seen := map[string]bool{}
		for _, description := range item.APIs {
			name := strings.TrimSpace(strings.SplitN(description, " at ", 2)[0])
			if name != "" && available[name] && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
		if len(names) < 2 {
			continue
		}
		if len(names) > maximum {
			names = shrinkLifecycle(names, maximum)
		}
		candidates = append(candidates, candidate{Functions: names, Score: lifecycleScore(names)})
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0].Functions
}

func fromNames(names []string, maximum int) []string {
	ordered := append([]string(nil), names...)
	sort.SliceStable(ordered, func(i, j int) bool { return nameScore(ordered[i]) > nameScore(ordered[j]) })
	var selected []string
	for _, name := range ordered {
		if len(selected) >= maximum {
			break
		}
		if nameScore(name) > 0 {
			selected = append(selected, name)
		}
	}
	return shrinkLifecycle(selected, maximum)
}

func shrinkLifecycle(names []string, maximum int) []string {
	if len(names) <= maximum {
		return names
	}
	selected := make([]string, 0, maximum)
	addCategory := func(predicate func(string) bool) {
		for _, name := range names {
			if len(selected) >= maximum {
				return
			}
			if predicate(name) && !contains(selected, name) {
				selected = append(selected, name)
				return
			}
		}
	}
	addCategory(isCreator)
	addCategory(isProcessor)
	addCategory(isCleanup)
	for _, name := range names {
		if len(selected) >= maximum {
			break
		}
		if !contains(selected, name) {
			selected = append(selected, name)
		}
	}
	return selected
}

func lifecycleScore(names []string) int {
	score := len(names)
	var creator, processor, cleanup bool
	for _, name := range names {
		creator = creator || isCreator(name)
		processor = processor || isProcessor(name)
		cleanup = cleanup || isCleanup(name)
		score += nameScore(name)
	}
	if creator && cleanup {
		score += 30
	}
	if creator && processor && cleanup {
		score += 20
	}
	return score
}

func nameScore(name string) int {
	score := 0
	if isCreator(name) {
		score += 8
	}
	if isProcessor(name) {
		score += 5
	}
	if isCleanup(name) {
		score += 8
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "hook") || strings.Contains(lower, "global") {
		score -= 5
	}
	return score
}

func isCreator(name string) bool {
	return hasAny(name, "create", "new", "init", "open", "parse", "load", "alloc")
}

func isProcessor(name string) bool {
	return hasAny(name, "process", "print", "write", "read", "get", "set", "update", "encode", "decode")
}

func isCleanup(name string) bool {
	return hasAny(name, "free", "delete", "destroy", "close", "cleanup", "release", "deinit")
}

func hasAny(value string, needles ...string) bool {
	lower := strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
