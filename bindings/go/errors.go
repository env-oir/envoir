package dmtapsync

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SyncError is a substrate refusal: the engine evaluated your input and said no.
//
// It carries the SYNC.md §12 registry entry verbatim — the same Code, Name and Action a JavaScript
// caller reads off the thrown error's message — so a Go product branches on the code rather than
// on prose, exactly as the other surfaces do. Matching on message text is how a fail-closed engine
// eventually takes the wrong refusal path.
//
//	var se *dmtapsync.SyncError
//	if errors.As(err, &se) && se.Code == "0x0A02" {
//	        // the signature did not verify; §12 says FAIL_CLOSED_BLOCK
//	}
type SyncError struct {
	// Code is the registry code, e.g. "0x0A02".
	Code string `json:"code"`
	// Name is the registry name, e.g. "ERR_SYNC_OP_SIG_INVALID".
	Name string `json:"name"`
	// Action is the §12 action a conformant implementation must take, e.g. "FAIL_CLOSED_BLOCK".
	Action string `json:"action"`
}

func (e *SyncError) Error() string {
	return fmt.Sprintf("dmtap sync refusal %s %s (%s)", e.Code, e.Name, e.Action)
}

// BindingError means the call itself was malformed — bad hex, unparseable JSON, a stale handle.
//
// Kept distinct from [SyncError] on purpose: "the engine refused your data" and "you called the
// binding wrong" are different bugs with different fixes, and collapsing them into one error type
// loses that at exactly the moment you need it.
type BindingError struct {
	// Message describes what could not be parsed or resolved.
	Message string `json:"message"`
}

func (e *BindingError) Error() string {
	return "dmtapsync: " + e.Message
}

// wireError is the envelope both classes arrive in.
type wireError struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Name    string `json:"name"`
	Action  string `json:"action"`
	Message string `json:"message"`
}

// parseError turns the module's structured message into the matching Go error.
//
// The message is a JSON document by design (see the Rust side's err module). If it ever is not,
// that is a bug in the binding rather than a refusal, and it surfaces as a BindingError carrying
// the raw text rather than being silently discarded.
func parseError(message string) error {
	var w wireError
	if err := json.Unmarshal([]byte(message), &w); err != nil {
		return &BindingError{Message: "unstructured error from the engine: " + message}
	}
	switch w.Error {
	case "sync":
		return &SyncError{Code: w.Code, Name: w.Name, Action: w.Action}
	case "binding":
		return &BindingError{Message: w.Message}
	default:
		return &BindingError{Message: "unrecognized error class from the engine: " + message}
	}
}

// AsSyncError reports whether err is a substrate refusal, and returns it if so.
//
// Sugar over [errors.As] for the common branch.
func AsSyncError(err error) (*SyncError, bool) {
	var se *SyncError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}

// IsRefusal reports whether err is a substrate refusal with the given registry code.
//
//	if dmtapsync.IsRefusal(err, "0x0A09") { /* divergence: §12 says HALT_ALERT */ }
func IsRefusal(err error, code string) bool {
	se, ok := AsSyncError(err)
	return ok && se.Code == code
}
