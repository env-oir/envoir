package dmtapsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The staleness guard for the committed wasm artifact.
//
// dmtap_sync_abi.wasm is committed, because a Go module has no build step: `go get` runs neither
// `go generate` nor build-abi.sh, so a gitignored artifact makes this module simply uncompilable
// for anyone consuming it normally. Both products that adopted the engine hit that and vendored
// the file by hand instead.
//
// But committing it re-opens the exact drift this repo has already been bitten by once: a stale
// checked-in module kept aborting on free long after src/abi.rs had been fixed, and the failure
// looked intermittent because whether it manifested depended on a String's capacity happening to
// equal its length. Nothing in git ties a binary blob to the source that produced it.
//
// So the blob is tied to its source here instead. wasm_provenance.json records a digest over every
// Rust input that feeds the artifact; this test recomputes that digest and fails when it moves.
// The check deliberately does NOT rebuild — a rebuild would need a Rust toolchain and a wasm32
// target, which a Go consumer has no reason to install, and a guard that hard-fails on a Go-only
// machine would be worse than no guard at all. Hashing source inputs needs nothing but the files.
//
// When it fails, the fix is to rebuild and re-record, not to edit the digest:
//
//	crates/dmtap-sync-wasm/build-abi.sh && go run ./bindings/go/internal/genprovenance
type provenance struct {
	SourceDigest   string            `json:"source_digest"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	ArtifactBytes  int               `json:"artifact_bytes"`
	BuiltFrom      string            `json:"built_from_commit"`
	Rustc          string            `json:"rustc"`
	Sources        map[string]string `json:"sources"`
}

func loadProvenance(t *testing.T) provenance {
	t.Helper()
	raw, err := os.ReadFile("wasm_provenance.json")
	if err != nil {
		t.Fatalf("reading wasm_provenance.json: %v", err)
	}
	var p provenance
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("parsing wasm_provenance.json: %v", err)
	}
	return p
}

// TestEmbeddedArtifactMatchesProvenance catches a committed blob that no longer matches the bytes
// recorded for it — corruption, a partial write, or a hand-edited file.
func TestEmbeddedArtifactMatchesProvenance(t *testing.T) {
	p := loadProvenance(t)
	sum := sha256.Sum256(engineWasm)
	if got := hex.EncodeToString(sum[:]); got != p.ArtifactSHA256 {
		t.Fatalf("embedded artifact does not match its provenance record:\n  embedded: %s (%d bytes)\n  recorded: %s (%d bytes)\nRebuild and re-record: crates/dmtap-sync-wasm/build-abi.sh",
			got, len(engineWasm), p.ArtifactSHA256, p.ArtifactBytes)
	}
}

// TestArtifactIsNotStaleAgainstSource is the guard that matters: it fails when the Rust source has
// moved since the artifact was built, which is the drift that previously shipped a real bug.
//
// It skips cleanly when the Rust sources are absent — a consumer who fetched only the Go module
// through the proxy has no crates/ directory, and there is nothing for them to verify or fix.
func TestArtifactIsNotStaleAgainstSource(t *testing.T) {
	p := loadProvenance(t)
	root := filepath.Join("..", "..")

	if _, err := os.Stat(filepath.Join(root, "crates", "dmtap-sync-wasm")); os.IsNotExist(err) {
		t.Skip("Rust sources not present (module fetched standalone) — nothing to check against")
	}

	paths := make([]string, 0, len(p.Sources))
	for path := range p.Sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	h := sha256.New()
	var missing, changed []string
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			missing = append(missing, path)
			continue
		}
		h.Write([]byte(path))
		h.Write(data)
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != p.Sources[path] {
			changed = append(changed, path)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("provenance lists sources that no longer exist: %v\nIf they were renamed or removed, rebuild and re-record.", missing)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != p.SourceDigest {
		t.Fatalf("dmtap_sync_abi.wasm is STALE against its source.\n  changed: %v\n  recorded digest: %s\n  current digest:  %s\nThe committed artifact was built from different code than is checked out. Rebuild it:\n  crates/dmtap-sync-wasm/build-abi.sh\nDo not edit wasm_provenance.json to silence this — the whole point is that the blob and the source agree.",
			changed, p.SourceDigest, got)
	}
}
