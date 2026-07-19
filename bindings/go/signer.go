package dmtapsync

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
)

// Signer produces an Ed25519 signature over a preimage the engine hands it.
//
// # Why this exists instead of a seed argument
//
// There is no entry point in this binding that accepts a private key, and adding one would be a
// security regression rather than a convenience. The engine runs inside a WebAssembly module whose
// linear memory is an ordinary byte slice on the Go heap: it is visible to anything that can read
// this process's memory, it is copied wholesale whenever the runtime grows it, it is not mlock'd,
// and it cannot be reliably zeroed. Handing a raw Ed25519 seed across that boundary would take a
// key that could have lived in an HSM, an agent, or a KMS and spread copies of it through a heap
// nothing is defending.
//
// So signing is detached, exactly as it is on the JS surface (which signs with a non-extractable
// WebCrypto CryptoKey for the same reason). The engine emits the RFC 9052 Sig_structure; your
// Signer signs it wherever the key actually lives; the engine verifies the result before it will
// assemble an envelope. The key never enters the module, and the module never asks for it.
//
// The insecure path is absent, not discouraged: TestNoEntryPointAcceptsKeyMaterial asserts the
// module's own dispatch table has no entry point that takes key material, so the property is
// checked on every run rather than maintained by remembering to be careful.
//
// # Implementing one
//
// The preimage is the exact bytes to sign — do not hash, prefix, or re-encode it. Return the raw
// 64-byte Ed25519 signature. Any error is propagated to the caller unchanged, and a custodian that
// silently fails cannot produce a valid envelope: the engine verifies before returning, so a wrong
// signature is caught here rather than on some other replica's ingest path hours later.
//
// Implementations must be safe for concurrent use if the surrounding [Instance] or [Pool] is used
// concurrently.
type Signer interface {
	// Public returns the Ed25519 public key this signer signs under. It must match the op's
	// author, and the engine will reject the envelope if it does not.
	Public() ed25519.PublicKey
	// Sign returns the Ed25519 signature over preimage.
	Sign(preimage []byte) ([]byte, error)
}

// SignerFunc adapts a function to [Signer], for a custodian that has no natural type.
type SignerFunc struct {
	// PublicKey is the key Sign signs under.
	PublicKey ed25519.PublicKey
	// SignFunc produces the signature.
	SignFunc func(preimage []byte) ([]byte, error)
}

// Public implements [Signer].
func (s SignerFunc) Public() ed25519.PublicKey { return s.PublicKey }

// Sign implements [Signer].
func (s SignerFunc) Sign(preimage []byte) ([]byte, error) { return s.SignFunc(preimage) }

// CryptoSigner adapts any [crypto.Signer] holding an Ed25519 key — including HSM, KMS, TPM and
// agent-backed implementations that never expose the key material — to [Signer].
//
// This is the intended path for production keys: the custodian keeps the key, this binding sees
// only signatures.
type CryptoSigner struct {
	// Key is the custodian. Its Public method must return an [ed25519.PublicKey].
	Key crypto.Signer
}

// Public implements [Signer].
func (c CryptoSigner) Public() ed25519.PublicKey {
	pub, _ := c.Key.Public().(ed25519.PublicKey)
	return pub
}

// Sign implements [Signer].
//
// Ed25519 signs the message itself rather than a digest, so the opts are zero per
// [ed25519.PrivateKey.Sign]'s contract.
func (c CryptoSigner) Sign(preimage []byte) ([]byte, error) {
	if _, ok := c.Key.Public().(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("dmtapsync: signer holds a %T, not an Ed25519 key", c.Key.Public())
	}
	return c.Key.Sign(nil, preimage, crypto.Hash(0))
}

// InMemorySigner signs with an [ed25519.PrivateKey] held in this process's memory.
//
// This is a legitimate and often correct choice — a native Go process has a memory model in which
// holding a secret key is a defensible thing to do, which is precisely the distinction that makes
// passing one *into* the WebAssembly module not defensible. It is offered for tests, for
// development, and for products whose threat model does not include process memory disclosure.
//
// For anything else, prefer [CryptoSigner] over a custodian that does not surrender the key. Note
// that whichever you choose, the key stays on the Go side of the boundary: the module receives a
// signature, never a seed.
type InMemorySigner struct {
	// PrivateKey is the signing key. Its public half must match the op's author.
	PrivateKey ed25519.PrivateKey
}

// Public implements [Signer].
func (m InMemorySigner) Public() ed25519.PublicKey {
	pub, _ := m.PrivateKey.Public().(ed25519.PublicKey)
	return pub
}

// Sign implements [Signer].
func (m InMemorySigner) Sign(preimage []byte) ([]byte, error) {
	if len(m.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("dmtapsync: private key is %d bytes, want %d",
			len(m.PrivateKey), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(m.PrivateKey, preimage), nil
}
