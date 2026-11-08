package promefuzz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CatalogFunction is a single selectable fuzz target in given mode.
type CatalogFunction struct {
	Name      string `json:"name"`
	Loc       string `json:"loc"`
	DeclLoc   string `json:"decl_loc,omitempty"`
	File      string `json:"file"`
	Public    bool   `json:"public"`
	Signature string `json:"signature,omitempty"`
}

// FunctionCatalog is the flat, user-selectable function list served to the UI
// after PromeFuzz preprocess, covering public APIs and internal functions.
type FunctionCatalog struct {
	GeneratedAt   time.Time         `json:"generated_at"`
	Count         int               `json:"count"`
	PublicCount   int               `json:"public_count"`
	InternalCount int               `json:"internal_count"`
	Functions     []CatalogFunction `json:"functions"`
}

type metaFile struct {
	Functions map[string]struct {
		Name    string `json:"name"`
		DeclLoc string `json:"declLoc"`
	} `json:"functions"`
}

type apiFile map[string]map[string][]struct {
	Loc string `json:"loc"`
}

type infoFile struct {
	FunctionInfos map[string]struct {
		Signature string `json:"signature"`
	} `json:"function_infos"`
}

// BuildFunctionCatalog reads the PromeFuzz preprocessor outputs under
// outputPath (meta.json = every function in the compiled sources, api.json =
// the public API subset, info.json = optional signatures) and produces a
// flat, user-selectable list of all functions — public and internal alike.
func BuildFunctionCatalog(outputPath string) (FunctionCatalog, error) {
	preprocessor := filepath.Join(outputPath, "preprocessor")
	var meta metaFile
	if err := readJSONFile(filepath.Join(preprocessor, "meta.json"), &meta); err != nil {
		return FunctionCatalog{}, fmt.Errorf("read meta.json: %w", err)
	}

	publicLocs := map[string]bool{}
	var api apiFile
	if err := readJSONFile(filepath.Join(preprocessor, "api.json"), &api); err == nil {
		for _, functions := range api {
			for _, locations := range functions {
				for _, location := range locations {
					if location.Loc != "" {
						publicLocs[location.Loc] = true
					}
				}
			}
		}
	}

	signatures := map[string]string{}
	var info infoFile
	if err := readJSONFile(filepath.Join(preprocessor, "info.json"), &info); err == nil {
		for loc, entry := range info.FunctionInfos {
			signatures[loc] = entry.Signature
		}
	}

	catalog := FunctionCatalog{GeneratedAt: time.Now()}
	for loc, entry := range meta.Functions {
		item := CatalogFunction{
			Name:    entry.Name,
			Loc:     loc,
			DeclLoc: entry.DeclLoc,
			File:    locFile(loc),
			Public:  publicLocs[loc],
		}
		item.Signature = signatures[loc]
		catalog.Functions = append(catalog.Functions, item)
	}
	sort.Slice(catalog.Functions, func(i, j int) bool {
		a, b := catalog.Functions[i], catalog.Functions[j]
		if a.Public != b.Public {
			return a.Public
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Loc < b.Loc
	})
	catalog.Count = len(catalog.Functions)
	for _, item := range catalog.Functions {
		if item.Public {
			catalog.PublicCount++
		}
	}
	catalog.InternalCount = catalog.Count - catalog.PublicCount
	return catalog, nil
}

func readJSONFile(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

// locFile extracts the file part from a PromeFuzz location string such as
// "/src/cJSON.c:1050:19".
func locFile(loc string) string {
	first := strings.LastIndex(loc, ":")
	if first < 0 {
		return loc
	}
	second := strings.LastIndex(loc[:first], ":")
	if second < 0 {
		return loc
	}
	return loc[:second]
}
