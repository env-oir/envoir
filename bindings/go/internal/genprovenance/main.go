// Command genprovenance re-records bindings/go/wasm_provenance.json after the wasm artifact is
// rebuilt. Run it immediately after crates/dmtap-sync-wasm/build-abi.sh; provenance_test.go fails
// until the record matches the source it was built from.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	root, err := repoRoot()
	if err != nil || !dirExists(filepath.Join(root, "crates")) {
		fatal("run this from inside the envoir checkout (need crates/ and bindings/go/): %v", err)
	}
	var srcs []string
	for _, pat := range []string{
		"crates/dmtap-sync-wasm/src/*.rs", "crates/dmtap-sync/src/*.rs",
		"crates/dmtap-sync-wasm/Cargo.toml", "crates/dmtap-sync-wasm/build-abi.sh",
	} {
		m, _ := filepath.Glob(filepath.Join(root, pat))
		for _, p := range m {
			rel, _ := filepath.Rel(root, p)
			srcs = append(srcs, filepath.ToSlash(rel))
		}
	}
	sort.Strings(srcs)

	h := sha256.New()
	files := map[string]string{}
	for _, rel := range srcs {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			fatal("reading %s: %v", rel, err)
		}
		h.Write([]byte(rel))
		h.Write(data)
		sum := sha256.Sum256(data)
		files[rel] = hex.EncodeToString(sum[:])
	}

	artPath := filepath.Join(root, "bindings", "go", "dmtap_sync_abi.wasm")
	art, err := os.ReadFile(artPath)
	if err != nil {
		fatal("reading artifact (run build-abi.sh first): %v", err)
	}
	artSum := sha256.Sum256(art)

	out := map[string]any{
		"_":                 "Provenance for the committed dmtap_sync_abi.wasm. See embed.go and provenance_test.go.",
		"source_digest":     hex.EncodeToString(h.Sum(nil)),
		"artifact_sha256":   hex.EncodeToString(artSum[:]),
		"artifact_bytes":    len(art),
		"built_from_commit": run(root, "git", "rev-parse", "HEAD"),
		"rustc":             run(root, "rustc", "--version"),
		"sources":           files,
	}
	buf, _ := json.MarshalIndent(out, "", "  ")
	dst := filepath.Join(root, "bindings", "go", "wasm_provenance.json")
	if err := os.WriteFile(dst, append(buf, '\n'), 0o644); err != nil {
		fatal("writing %s: %v", dst, err)
	}
	fmt.Printf("recorded %d sources, artifact %d bytes\n", len(files), len(art))
}

func dirExists(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	return strings.TrimSpace(string(out)), err
}

func run(dir, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
