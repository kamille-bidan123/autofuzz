package fuzzing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type APICoverageReport struct {
	Available   bool               `json:"available"`
	TotalAPIs   int                `json:"total_apis"`
	CoveredAPIs int                `json:"covered_apis"`
	Coverage    float64            `json:"coverage"`
	DriverCount int                `json:"driver_count"`
	APIs        []APICoverageEntry `json:"apis"`
	Error       string             `json:"error,omitempty"`
}

type APICoverageEntry struct {
	Name         string              `json:"name"`
	Header       string              `json:"header"`
	Location     string              `json:"location,omitempty"`
	DeclLocation string              `json:"decl_location,omitempty"`
	Covered      bool                `json:"covered"`
	Drivers      []APICoverageDriver `json:"drivers"`
}

type APICoverageDriver struct {
	DriverID int    `json:"driver_id"`
	Seq      int    `json:"seq,omitempty"`
	Source   string `json:"source,omitempty"`
}

type apiDriverSource struct {
	APICoverageDriver
	path string
}

// CollectAPICoverage reports which PromeFuzz-exported APIs are referenced by
// the latest known source for each generated child fuzz driver.
func CollectAPICoverage(targetDir string) (APICoverageReport, error) {
	outputPath := taskOutputPath(targetDir)
	apiPath := filepath.Join(outputPath, "preprocessor", "api.json")
	apis, err := loadExportedAPIs(apiPath)
	if err != nil {
		return APICoverageReport{Available: false, Error: err.Error()}, err
	}
	drivers := discoverAPIDriverSources(targetDir, outputPath)
	report := APICoverageReport{
		Available:   true,
		TotalAPIs:   len(apis),
		DriverCount: len(drivers),
		APIs:        apis,
	}
	coveredByName := map[string][]APICoverageDriver{}
	for _, driver := range drivers {
		names, err := extractDriverAPINames(driver.path, apis)
		if err != nil {
			continue
		}
		for name := range names {
			coveredByName[name] = appendDriverCoverage(coveredByName[name], driver.APICoverageDriver)
		}
	}
	for index := range report.APIs {
		drivers := coveredByName[report.APIs[index].Name]
		sort.Slice(drivers, func(i, j int) bool {
			if drivers[i].DriverID != drivers[j].DriverID {
				return drivers[i].DriverID < drivers[j].DriverID
			}
			return drivers[i].Seq < drivers[j].Seq
		})
		report.APIs[index].Drivers = drivers
		report.APIs[index].Covered = len(drivers) > 0
		if report.APIs[index].Covered {
			report.CoveredAPIs++
		}
	}
	if report.TotalAPIs > 0 {
		report.Coverage = float64(report.CoveredAPIs) / float64(report.TotalAPIs)
	}
	return report, nil
}

func CloneAPICoverageReport(report *APICoverageReport) *APICoverageReport {
	if report == nil {
		return nil
	}
	cloned := *report
	cloned.APIs = append([]APICoverageEntry(nil), report.APIs...)
	for index := range cloned.APIs {
		cloned.APIs[index].Drivers = append([]APICoverageDriver(nil), cloned.APIs[index].Drivers...)
	}
	return &cloned
}

func taskOutputPath(targetDir string) string {
	statePath := filepath.Join(targetDir, "agent-state.json")
	data, err := os.ReadFile(statePath)
	if err == nil {
		var state struct {
			OutputPath string `json:"output_path"`
		}
		if json.Unmarshal(data, &state) == nil && strings.TrimSpace(state.OutputPath) != "" {
			return state.OutputPath
		}
	}
	return filepath.Join(targetDir, "output")
}

func loadExportedAPIs(path string) ([]APICoverageEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read api.json: %w", err)
	}
	var raw map[string]map[string][]struct {
		Location     string `json:"loc"`
		DeclLocation string `json:"decl_loc"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse api.json: %w", err)
	}
	var entries []APICoverageEntry
	for header, functions := range raw {
		for name, locations := range functions {
			if len(locations) == 0 {
				entries = append(entries, APICoverageEntry{Name: name, Header: header})
				continue
			}
			for _, location := range locations {
				entries = append(entries, APICoverageEntry{
					Name:         name,
					Header:       header,
					Location:     location.Location,
					DeclLocation: location.DeclLocation,
				})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Header != entries[j].Header {
			return entries[i].Header < entries[j].Header
		}
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].DeclLocation < entries[j].DeclLocation
	})
	return entries, nil
}

func discoverAPIDriverSources(targetDir, outputPath string) []apiDriverSource {
	byID := map[int]apiDriverSource{}
	targetsRoot := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets")
	if entries, err := os.ReadDir(targetsRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "driver-") {
				continue
			}
			driverID := parseDriverDirName(entry.Name())
			if driverID <= 0 {
				continue
			}
			versionDir := latestAPITargetSnapshotDir(filepath.Join(targetsRoot, entry.Name()))
			if versionDir == "" {
				continue
			}
			source := targetSnapshotSource(versionDir, driverID)
			if source == "" {
				continue
			}
			byID[driverID] = apiDriverSource{
				APICoverageDriver: APICoverageDriver{DriverID: driverID, Seq: parseVersionDirName(filepath.Base(versionDir)), Source: source},
				path:              source,
			}
		}
	}
	for _, source := range generatedDriverSources(filepath.Join(outputPath, "fuzz_driver")) {
		driverID := generatedDriverID(source)
		if driverID <= 0 {
			continue
		}
		if _, exists := byID[driverID]; exists {
			continue
		}
		byID[driverID] = apiDriverSource{
			APICoverageDriver: APICoverageDriver{DriverID: driverID, Source: source},
			path:              source,
		}
	}
	drivers := make([]apiDriverSource, 0, len(byID))
	for _, driver := range byID {
		drivers = append(drivers, driver)
	}
	sort.Slice(drivers, func(i, j int) bool {
		return drivers[i].DriverID < drivers[j].DriverID
	})
	return drivers
}

func latestAPITargetSnapshotDir(targetRoot string) string {
	entries, err := os.ReadDir(targetRoot)
	if err != nil {
		return ""
	}
	latestSeq := 0
	latestDir := ""
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		seq := parseVersionDirName(entry.Name())
		if seq > latestSeq {
			latestSeq = seq
			latestDir = filepath.Join(targetRoot, entry.Name())
		}
	}
	return latestDir
}

func generatedDriverSources(driverDir string) []string {
	var out []string
	for _, pattern := range []string{"fuzz_driver_*.c", "fuzz_driver_*.cc", "fuzz_driver_*.cpp", "fuzz_driver_*.cxx"} {
		matches, _ := filepath.Glob(filepath.Join(driverDir, pattern))
		out = append(out, matches...)
	}
	sort.Strings(out)
	return out
}

func generatedDriverID(path string) int {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if !strings.HasPrefix(name, "fuzz_driver_") {
		return 0
	}
	id, _ := strconv.Atoi(strings.TrimPrefix(name, "fuzz_driver_"))
	return id
}

func extractDriverAPINames(path string, apis []APICoverageEntry) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	source := stripCXXCommentsAndLiterals(string(data))
	covered := map[string]bool{}
	for _, api := range apis {
		if covered[api.Name] {
			continue
		}
		for _, alias := range apiNameAliases(api.Name) {
			if alias != "" && apiCallPattern(alias).MatchString(source) {
				covered[api.Name] = true
				break
			}
		}
	}
	return covered, nil
}

func appendDriverCoverage(drivers []APICoverageDriver, driver APICoverageDriver) []APICoverageDriver {
	for _, existing := range drivers {
		if existing.DriverID == driver.DriverID {
			return drivers
		}
	}
	return append(drivers, driver)
}

func apiNameAliases(name string) []string {
	aliases := []string{name}
	if strings.Contains(name, "::") {
		parts := strings.Split(name, "::")
		aliases = append(aliases, parts[len(parts)-1])
	}
	return aliases
}

func apiCallPattern(name string) *regexp.Regexp {
	prefix := `(^|[^A-Za-z0-9_])`
	suffix := `\s*\(`
	if isIdentifier(name) {
		return regexp.MustCompile(prefix + regexp.QuoteMeta(name) + suffix)
	}
	return regexp.MustCompile(regexp.QuoteMeta(name) + suffix)
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for index, r := range s {
		if index == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func stripCXXCommentsAndLiterals(input string) string {
	const (
		code = iota
		lineComment
		blockComment
		stringLiteral
		charLiteral
		rawStringLiteral
	)
	var out strings.Builder
	out.Grow(len(input))
	state := code
	for i := 0; i < len(input); i++ {
		ch := input[i]
		next := byte(0)
		if i+1 < len(input) {
			next = input[i+1]
		}
		switch state {
		case code:
			switch {
			case ch == '/' && next == '/':
				out.WriteByte(' ')
				out.WriteByte(' ')
				i++
				state = lineComment
			case ch == '/' && next == '*':
				out.WriteByte(' ')
				out.WriteByte(' ')
				i++
				state = blockComment
			case ch == 'R' && next == '"':
				out.WriteByte(' ')
				out.WriteByte(' ')
				i++
				state = rawStringLiteral
			case ch == '"':
				out.WriteByte(' ')
				state = stringLiteral
			case ch == '\'':
				out.WriteByte(' ')
				state = charLiteral
			default:
				out.WriteByte(ch)
			}
		case lineComment:
			if ch == '\n' {
				out.WriteByte('\n')
				state = code
			} else {
				out.WriteByte(' ')
			}
		case blockComment:
			if ch == '*' && next == '/' {
				out.WriteByte(' ')
				out.WriteByte(' ')
				i++
				state = code
			} else if ch == '\n' {
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
		case stringLiteral:
			if ch == '\\' && next != 0 {
				out.WriteByte(' ')
				out.WriteByte(' ')
				i++
			} else if ch == '"' {
				out.WriteByte(' ')
				state = code
			} else if ch == '\n' {
				out.WriteByte('\n')
				state = code
			} else {
				out.WriteByte(' ')
			}
		case charLiteral:
			if ch == '\\' && next != 0 {
				out.WriteByte(' ')
				out.WriteByte(' ')
				i++
			} else if ch == '\'' {
				out.WriteByte(' ')
				state = code
			} else if ch == '\n' {
				out.WriteByte('\n')
				state = code
			} else {
				out.WriteByte(' ')
			}
		case rawStringLiteral:
			if ch == ')' && next == '"' {
				out.WriteByte(' ')
				out.WriteByte(' ')
				i++
				state = code
			} else if ch == '\n' {
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
		}
	}
	return out.String()
}
