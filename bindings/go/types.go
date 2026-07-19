package dmtapsync

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// HLC is a Hybrid Logical Clock timestamp (SYNC.md §3).
//
// The order is lexicographic by (Wall, Counter, Author), and because Author is a public key two
// distinct authors never tie — so the order is total across every replica, which is what makes
// "last write wins" mean the same thing everywhere.
type HLC struct {
	// Wall is the millisecond wall-clock component.
	Wall uint64 `json:"wall"`
	// Counter breaks ties within a millisecond.
	Counter uint32 `json:"counter"`
	// Author is the 32-byte Ed25519 public key, lowercase hex.
	Author string `json:"author"`
}

// AddTag is the causal evidence behind an OR-Set element: who added it, and when.
type AddTag struct {
	// Author is the adding replica's public key, lowercase hex.
	Author string `json:"author"`
	// HLC is the add's timestamp.
	HLC HLC `json:"hlc"`
}

// OpRef is an op's reference to another target (§7). Cross-namespace references are refused.
type OpRef struct {
	// Target is the referenced object.
	Target string `json:"target"`
	// HLC optionally pins the referenced version.
	HLC *HLC `json:"hlc,omitempty"`
}

// Op is a SyncOp: one operation in the six-kind CRDT algebra (§4.1).
//
// Values are tagged JSON — see [Text], [Bytes], [Int] and [Bool] — because JSON cannot tell a text
// string from a hex-spelled byte string, and the substrate's contract is that the bytes are the
// semantics (§2.2). An untagged value is refused rather than guessed at.
type Op struct {
	// Kind is one of the §4.2 op kinds; see [Instance.OpKinds] rather than hard-coding a number.
	Kind uint8 `json:"kind"`
	// NS is the namespace (§7). Empty is the default namespace.
	NS string `json:"ns"`
	// Target is the object this op acts on.
	Target string `json:"target"`
	// Field is the field within Target, for the kinds that have one.
	Field *string `json:"field,omitempty"`
	// Value is the tagged operand.
	Value json.RawMessage `json:"value,omitempty"`
	// HLC stamps the op and names its author.
	HLC HLC `json:"hlc"`
	// Observed carries the add-tags an OR-Set remove claims to have seen.
	Observed []AddTag `json:"observed,omitempty"`
	// Reference points at another target, for the kinds that reference one.
	Reference *OpRef `json:"reference,omitempty"`
}

// SigningInput is everything a key custodian needs to sign an op, and nothing that would require
// it to surrender the key (§4.1, RFC 9052).
//
// Sign [SigningInput.SigStructure] with Ed25519 under the key named by Author, then call
// [Instance.OpAttachSignature]. [Instance.SignOp] does both in one call.
type SigningInput struct {
	// Author is the key the op claims, lowercase hex — read out of the op's HLC, so the key you
	// sign with and the key the op claims are the same by construction.
	Author string `json:"author"`
	// Protected is the COSE protected header, lowercase hex.
	Protected string `json:"protected"`
	// ExternalAAD is the domain-separation tag binding this signature to SyncOps specifically, so
	// a signature minted for any other object cannot be replayed as one.
	ExternalAAD string `json:"external_aad"`
	// SigStructure is the exact preimage to sign, lowercase hex. Do not hash or re-encode it.
	SigStructure string `json:"sig_structure"`
}

// Bytes returns the decoded SigStructure — the bytes a [Signer] receives.
func (s SigningInput) Bytes() ([]byte, error) {
	b, err := hex.DecodeString(s.SigStructure)
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: signing input is not hex: %w", err)
	}
	return b, nil
}

// CoseParts are the four wire parts of a COSE_Sign1, decoded without being trusted.
//
// Decoding and trusting are deliberately separate steps: this tells you what an envelope claims,
// [Instance.VerifySignedOp] tells you whether the claim holds.
type CoseParts struct {
	// Protected is the protected header, lowercase hex.
	Protected string `json:"protected"`
	// Unprotected is always the empty map, "a0" — a non-empty one is refused.
	Unprotected string `json:"unprotected"`
	// Payload is the canonical op bytes, lowercase hex.
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, lowercase hex.
	Signature string `json:"signature"`
	// Alg is the COSE algorithm identifier.
	Alg int `json:"alg"`
	// Kid is the claimed key id, lowercase hex.
	Kid string `json:"kid"`
}

// LWWCell is the winning value for a last-write-wins field, or nil if there is none.
type LWWCell struct {
	// HLC is the winning write's timestamp.
	HLC HLC `json:"hlc"`
	// Value is the winning tagged value.
	Value json.RawMessage `json:"value"`
}

// CounterEntry is one author's contribution to a PN-counter (§4.6).
//
// Authors may only mutate their own entry; the union of per-author entries is what makes the merge
// associative.
type CounterEntry struct {
	// Author is the contributing replica's public key, lowercase hex.
	Author string `json:"author"`
	// P is the author's positive total.
	P int64 `json:"P"`
	// N is the author's negative total.
	N int64 `json:"N"`
}

// DeathState is an object's death dimension (§4.5).
type DeathState struct {
	// Deleted reports whether a death certificate dominates.
	Deleted bool `json:"deleted"`
	// Class is the deletion class token, nil when live.
	Class *string `json:"class"`
}

// Atom is one element of an RGA sequence, including tombstoned ones — §4.7 keeps them until the
// §6.2 stability cut, because a later insert may still cite one as its origin.
type Atom struct {
	// ID is the atom's element id.
	ID HLC `json:"id"`
	// Value is the atom's tagged value, absent for a tombstone.
	Value json.RawMessage `json:"value"`
	// Tombstoned reports whether the atom has been removed.
	Tombstoned bool `json:"tombstoned"`
}

// Sequence is an RGA sequence: the visible values, and the full atom order behind them.
type Sequence struct {
	// Values is the visible sequence, tombstones excluded.
	Values []json.RawMessage `json:"values"`
	// Atoms is every element id in order, tombstones included.
	Atoms []Atom `json:"atoms"`
}

// TreeMove records a move op's disposition during §4.8 replay.
type TreeMove struct {
	// HLC is the move's timestamp.
	HLC HLC `json:"hlc"`
	// Node is the moved node.
	Node string `json:"node"`
}

// Tree is a movable tree after cycle-safe replay (§4.8).
//
// A move that would close a cycle is skipped — deterministically and identically on every replica,
// so a skip is a convergent outcome rather than an error.
type Tree struct {
	// Edges is [node, parent, ordinal] per edge.
	Edges [][]string `json:"edges"`
	// Applied lists the moves that took effect.
	Applied []TreeMove `json:"applied"`
	// Skipped lists the moves skipped to preserve acyclicity.
	Skipped []TreeMove `json:"skipped"`
}

// Mark is one author's high-water mark in a version vector (§5.1).
type Mark struct {
	// Author is the replica's public key, lowercase hex.
	Author string `json:"author"`
	// HLC is the highest timestamp applied from that author.
	HLC HLC `json:"hlc"`
}

// Snapshot is a signed §6.1 checkpoint of observable state.
type Snapshot struct {
	// V is the object version.
	V uint8 `json:"v"`
	// Suite is the cryptographic suite identifier.
	Suite uint8 `json:"suite"`
	// NS is the namespace this snapshot covers.
	NS string `json:"ns"`
	// Covers is the version vector the snapshot stands in for.
	Covers []Mark `json:"covers"`
	// Root is the observable-state root, lowercase hex.
	Root string `json:"root"`
	// TS is the mint time in milliseconds.
	TS uint64 `json:"ts"`
	// Signer is the minting key, lowercase hex.
	Signer string `json:"signer"`
	// Sig is the signature, lowercase hex. Empty when unsigned.
	Sig string `json:"sig,omitempty"`
}

// FastJoin is the §5.2.1 answer a pull returns to a caller below the responder's truncation floor.
type FastJoin struct {
	// Snapshot is the checkpoint being offered.
	Snapshot Snapshot `json:"snapshot"`
	// Floor is the truncation floor the snapshot stands in for.
	Floor HLC `json:"floor"`
	// State optionally inlines the state body as hex — a cache hint held to the same hash check
	// as a fetched body, never a second source of truth.
	State *string `json:"state"`
}

// ObservableState is the canonical six-section projection two replicas compare (§6.1.1).
//
// Sections are tuple lists whose elements are of mixed type, so they are carried as raw JSON:
// re-marshaling a section reproduces exactly what the engine emitted, which matters because equal
// bytes are the definition of equal state.
type ObservableState struct {
	// ORSet holds [target, value] pairs.
	ORSet [][]json.RawMessage `json:"orset"`
	// LWW holds [target, field, value] triples.
	LWW [][]json.RawMessage `json:"lww"`
	// PN holds [target, field, total] triples, the total a decimal string.
	PN [][]json.RawMessage `json:"pn"`
	// Death holds [object, class] pairs.
	Death [][]json.RawMessage `json:"death"`
	// RGA holds [target, atoms] pairs.
	RGA [][]json.RawMessage `json:"rga"`
	// Tree holds [node, parent, ordinal] triples.
	Tree [][]json.RawMessage `json:"tree"`
}

// Fingerprint is a range-Merkle fold over a set of ops (§5.3).
//
// Count travels with the hash on purpose: without it, an empty range and a range whose ops happen
// to fold to the same value are indistinguishable.
type Fingerprint struct {
	// FP is the fold, lowercase hex.
	FP string `json:"fp"`
	// Count is how many ops it covers.
	Count uint64 `json:"count"`
}

// Summary is a [Fingerprint] restricted to the half-open range [Lo, Hi).
type Summary struct {
	// Lo is the inclusive lower bound.
	Lo HLC `json:"lo"`
	// Hi is the exclusive upper bound.
	Hi HLC `json:"hi"`
	// FP is the fold over the range, lowercase hex.
	FP string `json:"fp"`
	// Count is how many ops fall in the range.
	Count uint64 `json:"count"`
}

// OpEntry is one op's position and identity, the unit reconciliation works over.
type OpEntry struct {
	// HLC is the op's timestamp.
	HLC HLC `json:"hlc"`
	// ID is the op-id content address, lowercase hex.
	ID string `json:"id"`
}

// Reconciliation is the outcome of a recursive range-Merkle diff (§5.3).
//
// Matching (fp, count) prunes a whole range with nothing exchanged, which is the point: the cost
// tracks the size of the difference, not the size of the history.
type Reconciliation struct {
	// MissingHere lists op-ids the peer has and this replica does not, lowercase hex.
	MissingHere []string `json:"missing_here"`
	// MissingThere lists op-ids this replica has and the peer does not, lowercase hex.
	MissingThere []string `json:"missing_there"`
	// RangesCompared counts the ranges the recursion visited.
	RangesCompared uint64 `json:"ranges_compared"`
}

// RegistryEntry is one row of the 0x0A error registry (§12).
type RegistryEntry struct {
	// Code is the registry code.
	Code string `json:"code"`
	// Name is the registry name.
	Name string `json:"name"`
	// Action is the action a conformant implementation must take.
	Action string `json:"action"`
}

// OpKinds names the §4.2 op kinds, so a caller never hard-codes a magic number.
type OpKinds struct {
	// SetAdd adds an OR-Set element.
	SetAdd uint8 `json:"set_add"`
	// SetRemove removes an OR-Set element it has observed.
	SetRemove uint8 `json:"set_remove"`
	// LWWSet writes a last-write-wins field.
	LWWSet uint8 `json:"lww_set"`
	// Death mints a death certificate.
	Death uint8 `json:"death"`
	// Counter applies a PN-counter delta.
	Counter uint8 `json:"counter"`
	// SeqInsert inserts an RGA atom.
	SeqInsert uint8 `json:"seq_insert"`
	// SeqRemove tombstones an RGA atom.
	SeqRemove uint8 `json:"seq_remove"`
	// TreeMove reparents a node in a movable tree.
	TreeMove uint8 `json:"tree_move"`
}

// Version describes the binding and the substrate revision it speaks.
type Version struct {
	// Binding is the wrapper crate's version.
	Binding string `json:"binding"`
	// Engine names the core crate.
	Engine string `json:"engine"`
	// Substrate is the capability document revision.
	Substrate string `json:"substrate"`
	// Suite is the cryptographic suite identifier.
	Suite int `json:"suite"`
	// HLCSkewMS is the §3 skew bound in milliseconds.
	HLCSkewMS uint64 `json:"hlc_skew_ms"`
}

// --- tagged value constructors ---------------------------------------------------------------

// Text builds a tagged text value.
func Text(s string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"tstr": s})
	return b
}

// Bytes builds a tagged byte-string value.
func Bytes(b []byte) json.RawMessage {
	out, _ := json.Marshal(map[string]string{"bstr": hex.EncodeToString(b)})
	return out
}

// Int builds a tagged integer value.
//
// The substrate's integers are carried as JSON numbers and are therefore bounded by the exact
// integer range JavaScript can represent (±2^53) — a bound the engine checks rather than rounds
// past, so the three surfaces cannot disagree about a large value.
func Int(n int64) json.RawMessage {
	b, _ := json.Marshal(map[string]int64{"int": n})
	return b
}

// Bool builds a tagged boolean value.
func Bool(v bool) json.RawMessage {
	b, _ := json.Marshal(map[string]bool{"bool": v})
	return b
}
