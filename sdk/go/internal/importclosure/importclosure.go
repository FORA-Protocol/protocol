// Package importclosure finds every package of a module that a package is built from,
// for the guards that pin what that code may use.
//
// A guard that scans one directory pins nothing about the packages that directory
// imports: code that moves into one of them leaves the guard's reach and no test fails.
// The purity guards of sdk/go/helpers and sdk/go/core therefore scan every package of
// the module their package imports, directly or through another, as Walk computes it.
//
// It is test support, imported only by _test.go files. Like vectorio it takes no
// *testing.T and returns errors instead of failing, because a non-test package that
// imports testing registers the -test.* flags on every binary that links it. It reads
// import specs with go/parser rather than running the go command, so a guard needs
// nothing but the source tree.
package importclosure

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ModulePath reads the module path from the go.mod file in root.
func ModulePath(root string) (string, error) {
	f, err := os.Open(filepath.Join(root, "go.mod")) //nolint:gosec // the module's own go.mod
	if err != nil {
		return "", fmt.Errorf("importclosure: %w", err)
	}
	defer func() { _ = f.Close() }()
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		if path, ok := strings.CutPrefix(strings.TrimSpace(lines.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(path), `"`), nil
		}
	}
	if err := lines.Err(); err != nil {
		return "", fmt.Errorf("importclosure: read %s: %w", f.Name(), err)
	}
	return "", fmt.Errorf("importclosure: %s names no module", f.Name())
}

// Walk returns the directory of start and of every package of module that start
// imports, directly or through another, keyed by import path. root is the module's root
// directory: an import path module+"/x/y" lives in root/x/y.
//
// Only the imports of non-test files count, so a package that a test alone imports is
// not part of the closure. A package of the module whose directory is missing or holds
// no non-test Go file is an error, so an import path mapped wrongly cannot shrink the
// closure without a failure.
func Walk(root, module, start string) (map[string]string, error) {
	closure := map[string]string{}
	pending := []string{start}
	for len(pending) > 0 {
		path := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, seen := closure[path]; seen {
			continue
		}
		dir, err := dirOf(root, module, path)
		if err != nil {
			return nil, err
		}
		files, err := SourceFiles(dir)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("importclosure: %s is in %s, which holds no non-test Go file", path, dir)
		}
		closure[path] = dir
		for _, file := range files {
			imports, err := importsOf(file)
			if err != nil {
				return nil, err
			}
			for _, imp := range imports {
				if imp == module || strings.HasPrefix(imp, module+"/") {
					pending = append(pending, imp)
				}
			}
		}
	}
	return closure, nil
}

// SourceFiles returns the paths of the non-test Go files in dir, in name order.
func SourceFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("importclosure: %w", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out, nil
}

// dirOf maps an import path of module to its directory under root.
func dirOf(root, module, path string) (string, error) {
	if path == module {
		return root, nil
	}
	rest, ok := strings.CutPrefix(path, module+"/")
	if !ok {
		return "", fmt.Errorf("importclosure: %s is not a package of %s", path, module)
	}
	return filepath.Join(root, filepath.FromSlash(rest)), nil
}

// importsOf returns the import paths file names.
func importsOf(file string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		return nil, fmt.Errorf("importclosure: %w", err)
	}
	out := make([]string, 0, len(f.Imports))
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("importclosure: %s: %w", file, err)
		}
		out = append(out, path)
	}
	return out, nil
}
