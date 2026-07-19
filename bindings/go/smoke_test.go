package dmtapsync_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	dmtapsync "github.com/vul-os/envoir/bindings/go"
)

func TestSmoke(t *testing.T) {
	ctx := context.Background()
	t0 := time.Now()
	rt, err := dmtapsync.New(ctx)
	if err != nil { t.Fatal(err) }
	t.Logf("compile: %v  (artifact %d bytes)", time.Since(t0), dmtapsync.EngineWasmSize)
	defer rt.Close(ctx)

	t1 := time.Now()
	in, err := rt.Instance(ctx)
	if err != nil { t.Fatal(err) }
	t.Logf("instantiate: %v", time.Since(t1))
	defer in.Close(ctx)

	v, err := in.Version()
	if err != nil { t.Fatal(err) }
	t.Logf("version: %+v", v)

	names, err := in.EntryPoints()
	if err != nil { t.Fatal(err) }
	t.Logf("entry points: %d", len(names))

	// SYNC-OP-01's frozen bytes.
	author := "ca57eed30e4a7274ef4c648f56f58f880b20d2ca25725d9e5c13c83c08c09aeb"
	f := "x"
	op := dmtapsync.Op{Kind: 3, NS: "", Target: "a", Field: &f, Value: dmtapsync.Text("v"),
		HLC: dmtapsync.HLC{Wall: 1700000100000, Counter: 0, Author: author}}
	b, err := in.EncodeOp(op)
	if err != nil { t.Fatal(err) }
	got := hex.EncodeToString(b)
	want := "a60103026003616104617805617606a3011b0000018bcfe6eea00200035820ca57eed30e4a7274ef4c648f56f58f880b20d2ca25725d9e5c13c83c08c09aeb"
	if got != want { t.Fatalf("op bytes\n got %s\nwant %s", got, want) }

	// Detached signing round-trip.
	seed := make([]byte, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	op.HLC.Author = hex.EncodeToString(pub)
	ob, err := in.EncodeOp(op)
	if err != nil { t.Fatal(err) }
	cose, err := in.SignOp(ob, dmtapsync.InMemorySigner{PrivateKey: priv})
	if err != nil { t.Fatal(err) }
	back, err := in.VerifySignedOp(cose)
	if err != nil { t.Fatal(err) }
	if hex.EncodeToString(back) != hex.EncodeToString(ob) { t.Fatal("round-trip mismatch") }

	eng, err := in.NewEngine()
	if err != nil { t.Fatal(err) }
	defer eng.Close()
	newOp, err := eng.IngestSigned(cose, 1700000900000)
	if err != nil { t.Fatal(err) }
	t.Logf("ingested new=%v", newOp)
	cell, err := eng.LWWCell("a", "x")
	if err != nil { t.Fatal(err) }
	t.Logf("cell: %+v", cell)

	// A refusal must arrive with its registry code.
	err = in.CheckNsRef("a", "b")
	if !dmtapsync.IsRefusal(err, "0x0A0A") { t.Fatalf("want 0x0A0A, got %v", err) }
}
