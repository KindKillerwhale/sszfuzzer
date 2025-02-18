// fuzz_consensus_specs.go
//go:build gofuzz
// +build gofuzz

package consensus_fuzz

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/holiman/uint256"

	fssz "github.com/ferranbt/fastssz"
	kssz "github.com/karalabe/ssz"

	// Ethereum consensus spec types (Attestation, BeaconBlock, etc.)
	// types "github.com/karalabe/ssz/tests/testtypes/consensus-spec-tests"

	fastssz "github.com/KindKillerwhale/sszfuzzer/types/fastssz"
	types "github.com/KindKillerwhale/sszfuzzer/types/sszgen"
)

// commonPrefix returns the common prefix in two byte slices.
func commonPrefix(a []byte, b []byte) []byte {
	var prefix []byte

	for len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		prefix = append(prefix, a[0])
		a, b = a[1:], b[1:]
	}
	return prefix
}

// newableObject is a generic type whose purpose is to enforce that ssz.Object
// is specifically implemented on a struct pointer. That's needed to allow us
// to instantiate new structs via `new` when parsing.
type newableObject[U any] interface {
	kssz.Object
	*U
}

func FuzzConsensusSpecsAggregateAndProof(f *testing.F) {
	fuzzConsensusSpecType[*types.AggregateAndProof](f, "AggregateAndProof")
}
func FuzzConsensusSpecsAttestation(f *testing.F) {
	fuzzConsensusSpecType[*types.Attestation](f, "Attestation")
}
func FuzzConsensusSpecsAttestationData(f *testing.F) {
	fuzzConsensusSpecType[*types.AttestationData](f, "AttestationData")
}
func FuzzConsensusSpecsAttesterSlashing(f *testing.F) {
	fuzzConsensusSpecType[*types.AttesterSlashing](f, "AttesterSlashing")
}
func FuzzConsensusSpecsBeaconBlock(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlock](f, "BeaconBlock")
}
func FuzzConsensusSpecsBeaconBlockBody(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlockBody](f, "BeaconBlockBody")
}
func FuzzConsensusSpecsBeaconBlockBodyAltair(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlockBodyAltair](f, "BeaconBlockBody")
}
func FuzzConsensusSpecsBeaconBlockBodyBellatrix(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlockBodyBellatrix](f, "BeaconBlockBody")
}
func FuzzConsensusSpecsBeaconBlockBodyCapella(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlockBodyCapella](f, "BeaconBlockBody")
}
func FuzzConsensusSpecsBeaconBlockBodyDeneb(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlockBodyDeneb](f, "BeaconBlockBody")
}
func FuzzConsensusSpecsBeaconBlockHeader(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlockHeader](f, "BeaconBlockHeader")
}
func FuzzConsensusSpecsBeaconState(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconState](f, "BeaconState")
}
func FuzzConsensusSpecsBeaconStateAltair(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconStateAltair](f, "BeaconState")
}
func FuzzConsensusSpecsBeaconStateBellatrix(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconStateBellatrix](f, "BeaconState")
}
func FuzzConsensusSpecsBeaconStateCapella(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconStateCapella](f, "BeaconState")
}
func FuzzConsensusSpecsBeaconStateDeneb(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconStateDeneb](f, "BeaconState")
}
func FuzzConsensusSpecsBLSToExecutionChange(f *testing.F) {
	fuzzConsensusSpecType[*types.BLSToExecutionChange](f, "BLSToExecutionChange")
}
func FuzzConsensusSpecsCheckpoint(f *testing.F) {
	fuzzConsensusSpecType[*types.Checkpoint](f, "Checkpoint")
}
func FuzzConsensusSpecsDeposit(f *testing.F) {
	fuzzConsensusSpecType[*types.Deposit](f, "Deposit")
}
func FuzzConsensusSpecsDepositData(f *testing.F) {
	fuzzConsensusSpecType[*types.DepositData](f, "DepositData")
}
func FuzzConsensusSpecsDepositMessage(f *testing.F) {
	fuzzConsensusSpecType[*types.DepositMessage](f, "DepositMessage")
}
func FuzzConsensusSpecsEth1Block(f *testing.F) {
	fuzzConsensusSpecType[*types.Eth1Block](f, "Eth1Block")
}
func FuzzConsensusSpecsEth1Data(f *testing.F) {
	fuzzConsensusSpecType[*types.Eth1Data](f, "Eth1Data")
}
func FuzzConsensusSpecsExecutionPayload(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayload](f, "ExecutionPayload")
}
func FuzzConsensusSpecsExecutionPayloadCapella(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadCapella](f, "ExecutionPayload")
}
func FuzzConsensusSpecsExecutionPayloadDeneb(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadDeneb](f, "ExecutionPayload")
}
func FuzzConsensusSpecsExecutionPayloadHeader(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadHeader](f, "ExecutionPayloadHeader")
}
func FuzzConsensusSpecsExecutionPayloadHeaderCapella(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadHeaderCapella](f, "ExecutionPayloadHeader")
}
func FuzzConsensusSpecsExecutionPayloadHeaderDeneb(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadHeaderDeneb](f, "ExecutionPayloadHeader")
}
func FuzzConsensusSpecsFork(f *testing.F) {
	fuzzConsensusSpecType[*types.Fork](f, "Fork")
}
func FuzzConsensusSpecsHistoricalBatch(f *testing.F) {
	fuzzConsensusSpecType[*types.HistoricalBatch](f, "HistoricalBatch")
}
func FuzzConsensusSpecsHistoricalSummary(f *testing.F) {
	fuzzConsensusSpecType[*types.HistoricalSummary](f, "HistoricalSummary")
}
func FuzzConsensusSpecsIndexedAttestation(f *testing.F) {
	fuzzConsensusSpecType[*types.IndexedAttestation](f, "IndexedAttestation")
}
func FuzzConsensusSpecsPendingAttestation(f *testing.F) {
	fuzzConsensusSpecType[*types.PendingAttestation](f, "PendingAttestation")
}
func FuzzConsensusSpecsProposerSlashing(f *testing.F) {
	fuzzConsensusSpecType[*types.ProposerSlashing](f, "ProposerSlashing")
}
func FuzzConsensusSpecsSignedBeaconBlockHeader(f *testing.F) {
	fuzzConsensusSpecType[*types.SignedBeaconBlockHeader](f, "SignedBeaconBlockHeader")
}
func FuzzConsensusSpecsSignedBLSToExecutionChange(f *testing.F) {
	fuzzConsensusSpecType[*types.SignedBLSToExecutionChange](f, "SignedBLSToExecutionChange")
}
func FuzzConsensusSpecsSignedVoluntaryExit(f *testing.F) {
	fuzzConsensusSpecType[*types.SignedVoluntaryExit](f, "SignedVoluntaryExit")
}
func FuzzConsensusSpecsSyncAggregate(f *testing.F) {
	fuzzConsensusSpecType[*types.SyncAggregate](f, "SyncAggregate")
}
func FuzzConsensusSpecsSyncCommittee(f *testing.F) {
	fuzzConsensusSpecType[*types.SyncCommittee](f, "SyncCommittee")
}
func FuzzConsensusSpecsValidator(f *testing.F) {
	fuzzConsensusSpecType[*types.Validator](f, "Validator")
}
func FuzzConsensusSpecsVoluntaryExit(f *testing.F) {
	fuzzConsensusSpecType[*types.VoluntaryExit](f, "VoluntaryExit")
}
func FuzzConsensusSpecsWithdrawal(f *testing.F) {
	fuzzConsensusSpecType[*types.Withdrawal](f, "Withdrawal")
}

func FuzzConsensusSpecsBeaconBlockBodyMonolith(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconBlockBodyMonolith](f, "BeaconBlockBody")
}
func FuzzConsensusSpecsBeaconStateMonolith(f *testing.F) {
	fuzzConsensusSpecType[*types.BeaconStateMonolith](f, "BeaconState")
}
func FuzzConsensusSpecsExecutionPayloadMonolith(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadMonolith](f, "ExecutionPayload")
}
func FuzzConsensusSpecsExecutionPayloadHeaderMonolith(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadHeaderMonolith](f, "ExecutionPayloadHeader")
}

func FuzzConsensusSpecsExecutionPayloadVariation(f *testing.F) {
	fuzzConsensusSpecType[*types.ExecutionPayloadVariation](f, "ExecutionPayload")
}
func FuzzConsensusSpecsHistoricalBatchVariation(f *testing.F) {
	fuzzConsensusSpecType[*types.HistoricalBatchVariation](f, "HistoricalBatch")
}
func FuzzConsensusSpecsWithdrawalVariation(f *testing.F) {
	fuzzConsensusSpecType[*types.WithdrawalVariation](f, "Withdrawal")
}

func fuzzConsensusSpecType[T newableObject[U], U any](f *testing.F, kind string) {
	// Fuzz logic
	f.Fuzz(func(t *testing.T, inSSZ []byte) {
		tm := NewTraceManager()

		tm.recordStep("StartFuzz", len(inSSZ))

		var valid bool

		// (a) Try stream-based decode/encode roundtrip
		{
			obj := T(new(U))
			if decodeStreamRoundtrip(t, tm, inSSZ, obj) {
				// If decode/encode succeeded, run final checks
				finalChecks(t, inSSZ, obj)

				// Do differential fuzz check
				if differentialCheckFastssz[T, U](t, tm, inSSZ) {
					valid = true
				}
			}
		}

		// (b) If not valid yet, try buffer-based decode/encode roundtrip
		if !valid {
			obj2 := T(new(U))
			if decodeBufferRoundtrip(t, tm, inSSZ, obj2) {
				finalChecks(t, inSSZ, obj2)

				// Do differential fuzz check
				if differentialCheckFastssz[T, U](t, tm, inSSZ) {
					valid = true
				}
			}
		}

		// (c) If valid => do extra stateful/crossFork checks (handleValidCase)
		if valid {
			handleValidCase[T, U](t, tm, inSSZ)
		}
	})
}

/*
// collectValidCorpus enumerates each fork's ssz_random data,
// decodes them with ForkFuture and returns a list of valid SSZ byte
func collectValidCorpus[T newableObject[U], U any](f *testing.F, kind string, consensusSpecTestsRoot string) (valid [][]byte) {
	// Iterate over all the forks and collect all the sample data
	forks, err := os.ReadDir(consensusSpecTestsRoot)
	if err != nil {
		f.Errorf("failed to walk spec collection %v: %v", consensusSpecTestsRoot, err)
		return nil
	}

	var valids [][]byte

	for _, fork := range forks {
		// Skip test cases for types introduced in later forks
		path := filepath.Join(consensusSpecTestsRoot, fork.Name(), "ssz_static", kind, "ssz_random")

		if _, err := os.Stat(path); err != nil {
			continue // skip forks that do not have this type
		}

		tests, err := os.ReadDir(path)
		if err != nil {
			f.Errorf("failed to walk test collection %v: %v", path, err)
			return
		}

		// Feed all the valid test data into the fuzzer
		for _, test := range tests {
			inSnappy, err := os.ReadFile(filepath.Join(path, test.Name(), "serialized.ssz_snappy"))
			if err != nil {
				// Assume no broken file => fatal
				// If a broken file exists, Fatal will have to be changed to Error or Log + continue
				f.Fatalf("failed to load snapy ssz binary: %v", err)
			}

			// decode => if success => store
			inSSZ, err := snappy.Decode(nil, inSnappy)
			if err != nil {
				f.Fatalf("failed to parse snappy ssz binary %v: %v", path, err)
			}

			obj := T(new(U))
			if err := kssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), kssz.ForkFuture); err == nil {
				// Stash away all valid ssz streams so we can play with decoding
				// into previously used objects
				valids = append(valids, inSSZ)

				// Add the valid ssz stream to the fuzzer
				f.Add(inSSZ)
			} // else {
			// Confirm that broken file do not exist
			// f.Fatalf("unexpected decode error => the file might be broken %v: %v", path, err)
			// f.Logf("unexpected decode error => the file might be broken %v: %v", path, err)
			// }
		}
	}
	return valids
}
*/

// decodeStreamRoundtrip tries decoding the SSZ bytes in streaming mode,
// then re-encodes them in streaming mode again, compares, and returns true if they match.
func decodeStreamRoundtrip[T newableObject[U], U any](t *testing.T, tm *traceManager, inSSZ []byte, obj T) bool {
	r := bytes.NewReader(inSSZ)
	err := kssz.DecodeFromStreamOnFork(r, obj, uint32(len(inSSZ)), kssz.ForkFuture)

	// Calculate leftover
	leftover := r.Len()
	tm.recordStep("DecodeFromStreamOnFork", leftover)

	if err != nil {
		// decode false -> roundtrip impossible
		return false
	}

	// Stream decoder succeeded, make sure it re-encodes correctly and
	// that the buffer decoder also succeeds parsing
	blob := new(bytes.Buffer)
	if err := kssz.EncodeToStreamOnFork(blob, obj, kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)

		t.Fatalf("failed to re-encode stream: %v", err)
	}

	tm.recordStep("EncodeToStreamOnFork", blob.Len())

	if !bytes.Equal(blob.Bytes(), inSSZ) {
		prefix := commonPrefix(blob.Bytes(), inSSZ)
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("re-encoded stream mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			blob, inSSZ, len(prefix), blob.Bytes()[len(prefix):], inSSZ[len(prefix):])
	}

	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("failed to decode buffer: %v", err)
	}
	return true
}

// decodeBufferRoundtrip tries decoding the SSZ bytes in buffer mode,
// then re-encodes them in buffer mode again, compares, and returns true if they match.
func decodeBufferRoundtrip[T newableObject[U], U any](t *testing.T, tm *traceManager, inSSZ []byte, obj T) bool {
	// Try the buffer encoder/decoder
	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		return false
	}

	// leftover : the buffer method does not have a clear byte concept, so 0
	tm.recordStep("DecodeFromBytesOnFork", 0)

	// Buffer decoder succeeded, make sure it re-encodes correctly and
	// that the stream decoder also succeeds parsing
	bin := make([]byte, kssz.SizeOnFork(obj, kssz.ForkFuture))
	if err := kssz.EncodeToBytesOnFork(bin, obj, kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("failed to re-encode buffer: %v", err)
	}

	tm.recordStep("EncodeToBytesOnFork", len(bin))

	if !bytes.Equal(bin, inSSZ) {
		prefix := commonPrefix(bin, inSSZ)
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("re-encoded buffer mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			bin, inSSZ, len(prefix), bin[len(prefix):], inSSZ[len(prefix):])
	}

	r := bytes.NewReader(inSSZ)
	if err := kssz.DecodeFromStreamOnFork(r, obj, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("failed to decode stream: %v", err)
	}

	tm.recordStep("DecodeFromStreamOnFork", r.Len())

	return true
}

// finalChecks verifies that concurrent vs sequential merkle root match,
// and that size matches the input length, etc.
func finalChecks[T newableObject[U], U any](t *testing.T, inSSZ []byte, obj T) {
	hashSeq := kssz.HashSequentialOnFork(obj, kssz.ForkFuture)
	hashConc := kssz.HashConcurrentOnFork(obj, kssz.ForkFuture)

	if hashSeq != hashConc {
		t.Fatalf("sequential/concurrent hash mismatch: sequencial %x, concurrent %x", hashSeq, hashConc)
	}

	sz := kssz.SizeOnFork(obj, kssz.ForkFuture)
	if sz != uint32(len(inSSZ)) {
		t.Fatalf("reported/generated size mismatch: reported %v, generated %v", sz, len(inSSZ))
	}
}

// --------------------------------------------------------
// handleValidCase (stateful leftover decode, crossForkCheck)
// --------------------------------------------------------

func handleValidCase[T newableObject[U], U any](t *testing.T, tm *traceManager, inSSZ []byte) {

	// Try the stream encoder/decoder into a prepped object
	obj := T(new(U))

	if cl, ok := any(obj).(interface{ ClearSSZ() }); ok {
		// t.Logf("===> ClearSSZ() is found and will be called!")
		cl.ClearSSZ()
	} else {
		t.Errorf("===> ClearSSZ() not found on this type.")
	}

	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		panic(err) // we've already decoded this, cannot fail
	}
	tm.recordStep("handleValidCase-DecodeFromBytesOnFork", 0)

	r := bytes.NewReader(inSSZ)
	if err := kssz.DecodeFromStreamOnFork(r, obj, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)

		t.Fatalf("failed to decode stream into used object: %v", err)
	}

	leftover := r.Len()
	tm.recordStep("handleValidCase-DecodeFromStreamOnFork", leftover)

	blob := new(bytes.Buffer)
	if err := kssz.EncodeToStreamOnFork(blob, obj, kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("failed to re-encode stream from used object: %v", err)
	}

	tm.recordStep("handleValidCase-EncodeToStreamOnFork", blob.Len())

	if !bytes.Equal(blob.Bytes(), inSSZ) {
		prefix := commonPrefix(blob.Bytes(), inSSZ)
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("re-encoded stream from used object mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			blob, inSSZ, len(prefix), blob.Bytes()[len(prefix):], inSSZ[len(prefix):])
	}

	finalChecks(t, inSSZ, obj)

	// Try the buffer encoder/decoder into a prepped object
	obj = T(new(U))

	if cl, ok := any(obj).(interface{ ClearSSZ() }); ok {
		cl.ClearSSZ()
	}

	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		panic(err) // we've already decoded this, cannot fail
	}
	tm.recordStep("handleValidCase-DecodeFromBytesOnFork", 0)

	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("failed to decode buffer into used object: %v", err)
	}
	tm.recordStep("handleValidCase-DecodeFromBytesOnFork", 0)

	bin := make([]byte, kssz.SizeOnFork(obj, kssz.ForkFuture))
	if err := kssz.EncodeToBytesOnFork(bin, obj, kssz.ForkFuture); err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("failed to re-encode buffer from used object: %v", err)
	}
	tm.recordStep("handleValidCase-EncodeToBytesOnFork", len(bin))

	if !bytes.Equal(bin, inSSZ) {
		prefix := commonPrefix(bin, inSSZ)
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)
		t.Fatalf("re-encoded buffer from used object mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			bin, inSSZ, len(prefix), bin[len(prefix):], inSSZ[len(prefix):])
	}

	finalChecks(t, inSSZ, obj)

	// cross fork decode
	crossForkCheck(t, tm, inSSZ, obj)
}

// crossForkCheck : decode 'inSSZ' for all known forks => coverage
func crossForkCheck[T newableObject[U], U any](t *testing.T, tm *traceManager, inSSZ []byte, obj T) {
	for forkName, forkVal := range kssz.ForkMapping {
		// skip unknown => or keep it if you want
		if forkVal == kssz.ForkUnknown {
			continue
		}

		if cl, ok := any(obj).(interface{ ClearSSZ() }); ok {
			cl.ClearSSZ()
		}

		r := bytes.NewReader(inSSZ)
		err := kssz.DecodeFromStreamOnFork(r, obj, uint32(len(inSSZ)), forkVal)

		leftover := r.Len() // leftover
		tm.recordStep(fmt.Sprintf("crossFork-decode-%s", forkName), leftover)

		if err == nil {
			// success => re-encode just for coverage
			sz2 := kssz.SizeOnFork(obj, forkVal)
			out := make([]byte, sz2)
			if err2 := kssz.EncodeToBytesOnFork(out, obj, forkVal); err2 == nil {
				// success => leftover = len(out)
				tm.recordStep(fmt.Sprintf("crossFork-encode-%s", forkName), len(out))

				// t.Logf("[crossFork] fork=%s => decode+encode ok (size=%d)", forkName, sz2)
				continue
			} else {
				scenario := tm.buildScenario(inSSZ)
				dumpTraceScenario(scenario)

				t.Fatalf("[crossFork] fork=%s => re-encode fail: %v", forkName, err2)
				// t.Logf("[crossFork] fork=%s => re-encode fail: %v", forkName, err2)
			}
		} else {
			t.Logf("[crossFork] fork=%s => decode fail: %v", forkName, err)
		}
	}
}

// Object is the interface implented by fastssz types.
type Object interface {
	fssz.Marshaler
	fssz.Unmarshaler
	fssz.HashRoot
}

// cache for bridged objects
var bridgedCache sync.Map // map[uintptr]any

func BridgeKaralabeToFastssz(k any) (any, error) {
	if k == nil {
		return nil, nil
	}
	rv := reflect.ValueOf(k)
	// cache key is the pointer value
	if rv.Kind() != reflect.Ptr {
		if rv.CanAddr() {
			rv = rv.Addr()
		} else {
			// not addressable => return directly
			fmt.Printf("BridgeKaralabeToFastssz: not addressable => return directly\n")
			return bridgeValue(rv)
		}
	}
	key := rv.Pointer()
	if cached, ok := bridgedCache.Load(key); ok {
		return cached, nil
	}

	result, err := bridgeValue(rv)
	if err != nil {
		return nil, err
	}

	bridgedCache.Store(key, result)
	return result, nil
}

type fastsszFactoryFunc func() Object

const basePackage = "github.com/KindKillerwhale/sszfuzzer/types/sszgen"

var fastsszFactoryMapping = map[string]fastsszFactoryFunc{
	"AggregateAndProof":              func() Object { return &fastssz.AggregateAndProof{} },
	"Attestation":                    func() Object { return &fastssz.Attestation{} },
	"AttestationData":                func() Object { return &fastssz.AttestationData{} },
	"AttesterSlashing":               func() Object { return &fastssz.AttesterSlashing{} },
	"BeaconBlock":                    func() Object { return &fastssz.BeaconBlock{} },
	"BeaconBlockBody":                func() Object { return &fastssz.BeaconBlockBody{} },
	"BeaconBlockBodyAltair":          func() Object { return &fastssz.BeaconBlockBodyAltair{} },
	"BeaconBlockBodyBellatrix":       func() Object { return &fastssz.BeaconBlockBodyBellatrix{} },
	"BeaconBlockBodyCapella":         func() Object { return &fastssz.BeaconBlockBodyCapella{} },
	"BeaconBlockBodyDeneb":           func() Object { return &fastssz.BeaconBlockBodyDeneb{} },
	"BeaconBlockBodyMonolith":        func() Object { return &fastssz.BeaconBlockBodyMonolith{} },
	"BeaconBlockHeader":              func() Object { return &fastssz.BeaconBlockHeader{} },
	"BeaconState":                    func() Object { return &fastssz.BeaconState{} },
	"BeaconStateAltair":              func() Object { return &fastssz.BeaconStateAltair{} },
	"BeaconStateBellatrix":           func() Object { return &fastssz.BeaconStateBellatrix{} },
	"BeaconStateCapella":             func() Object { return &fastssz.BeaconStateCapella{} },
	"BeaconStateDeneb":               func() Object { return &fastssz.BeaconStateDeneb{} },
	"BeaconStateMonolith":            func() Object { return &fastssz.BeaconStateMonolith{} },
	"BLSToExecutionChange":           func() Object { return &fastssz.BLSToExecutionChange{} },
	"Checkpoint":                     func() Object { return &fastssz.Checkpoint{} },
	"Deposit":                        func() Object { return &fastssz.Deposit{} },
	"DepositData":                    func() Object { return &fastssz.DepositData{} },
	"DepositMessage":                 func() Object { return &fastssz.DepositMessage{} },
	"Eth1Block":                      func() Object { return &fastssz.Eth1Block{} },
	"Eth1Data":                       func() Object { return &fastssz.Eth1Data{} },
	"ExecutionPayload":               func() Object { return &fastssz.ExecutionPayload{} },
	"ExecutionPayloadCapella":        func() Object { return &fastssz.ExecutionPayloadCapella{} },
	"ExecutionPayloadDeneb":          func() Object { return &fastssz.ExecutionPayloadDeneb{} },
	"ExecutionPayloadHeader":         func() Object { return &fastssz.ExecutionPayloadHeader{} },
	"ExecutionPayloadHeaderCapella":  func() Object { return &fastssz.ExecutionPayloadHeaderCapella{} },
	"ExecutionPayloadHeaderDeneb":    func() Object { return &fastssz.ExecutionPayloadHeaderDeneb{} },
	"ExecutionPayloadHeaderMonolith": func() Object { return &fastssz.ExecutionPayloadHeaderMonolith{} },
	"ExecutionPayloadMonolith":       func() Object { return &fastssz.ExecutionPayloadMonolith{} },
	"ExecutionPayloadVariation":      func() Object { return &fastssz.ExecutionPayloadVariation{} },
	"Fork":                           func() Object { return &fastssz.Fork{} },
	"HistoricalBatch":                func() Object { return &fastssz.HistoricalBatch{} },
	"HistoricalBatchVariation":       func() Object { return &fastssz.HistoricalBatchVariation{} },
	"HistoricalSummary":              func() Object { return &fastssz.HistoricalSummary{} },
	"IndexedAttestation":             func() Object { return &fastssz.IndexedAttestation{} },
	"PendingAttestation":             func() Object { return &fastssz.PendingAttestation{} },
	"ProposerSlashing":               func() Object { return &fastssz.ProposerSlashing{} },
	"SignedBeaconBlockHeader":        func() Object { return &fastssz.SignedBeaconBlockHeader{} },
	"SignedBLSToExecutionChange":     func() Object { return &fastssz.SignedBLSToExecutionChange{} },
	"SignedVoluntaryExit":            func() Object { return &fastssz.SignedVoluntaryExit{} },
	"SyncAggregate":                  func() Object { return &fastssz.SyncAggregate{} },
	"SyncCommittee":                  func() Object { return &fastssz.SyncCommittee{} },
	"Validator":                      func() Object { return &fastssz.Validator{} },
	"VoluntaryExit":                  func() Object { return &fastssz.VoluntaryExit{} },
	"Withdrawal":                     func() Object { return &fastssz.Withdrawal{} },
	"WithdrawalVariation":            func() Object { return &fastssz.WithdrawalVariation{} },
}

func newFastsszObjectByType(rt reflect.Type) (Object, error) {
	if rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}
	if rt.PkgPath() != basePackage {
		return nil, fmt.Errorf("unsupported package: %s", rt.PkgPath())
	}
	if factory, ok := fastsszFactoryMapping[rt.Name()]; ok {
		return factory(), nil
	}
	return nil, fmt.Errorf("unmapped type: %s", rt.Name())
}

func newFastsszObject[T any]() (Object, error) {
	var zero T
	return newFastsszObjectByType(reflect.TypeOf(zero))
}

func newFastsszObjectFromKaralabeType(typ reflect.Type) (Object, error) {
	return newFastsszObjectByType(typ)
}

func differentialCheckFastssz[T newableObject[U], U any](t *testing.T, tm *traceManager, inSSZ []byte) bool {
	// 1) Decode with karalabe/ssz
	objKaralabe := T(new(U))

	if cl, ok := any(objKaralabe).(interface{ ClearSSZ() }); ok {
		cl.ClearSSZ()
	}

	if err := kssz.DecodeFromBytesOnFork(inSSZ, objKaralabe, kssz.ForkFuture); err != nil {
		// If karalabe fails => no comparison
		t.Logf("[DiffFuzz] karalabe/ssz decode fail: %v\n", err)
		return false
	}

	// leftover = ?
	tm.recordStep("DiffFuzz-DecodeFromBytesOnFork", 0)

	// 2) Decode with fastssz
	objFastssz, err := newFastsszObject[T]()
	if err != nil {
		t.Logf("[DiffFuzz] no fastssz mapping for %T => skip: %v\n", objKaralabe, err)
		return false
	}

	if err := objFastssz.UnmarshalSSZ(inSSZ); err != nil {
		t.Logf("[DiffFuzz] fastssz decode fail: %v\n", err)
		return false
	}

	tm.recordStep("DiffFuzz-fastssz-UnmarshalSSZ", 0)

	// 3) karalabe -> fastssz Bridging
	bridged, err := BridgeKaralabeToFastssz(objKaralabe)
	if err != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)

		t.Fatalf("[DiffFuzz] bridging karalabe->fastssz error: %v\n", err)
		return false
	}

	// 3) bridged vs objFastssz
	diff := cmp.Diff(bridged, objFastssz)
	if diff != "" {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)

		t.Fatalf("[DiffFuzz] Decoded object mismatch => (karalabe->bridged) vs fastssz\nDiff:\n%s", diff)
		return false
	}

	// 4) Re-encode with fastssz (bridged vs direct)
	outF1, err1 := marshalAsFastssz(bridged)
	if err1 != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)

		t.Fatalf("[DiffFuzz] fail to re-encode bridged (fastssz): %v", err1)
		return false
	}
	tm.recordStep("DiffFuzz-encoded-bridged", len(outF1))

	outF2, err2 := objFastssz.MarshalSSZ()
	if err2 != nil {
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)

		t.Fatalf("[DiffFuzz] fastssz re-encode fail: %v", err2)
		return false
	}
	tm.recordStep("DiffFuzz-encoded-fastssz", len(outF2))

	// 5) Compare re-encoded bytes
	if !bytes.Equal(outF1, outF2) {
		prefix := commonPrefix(outF1, outF2)
		scenario := tm.buildScenario(inSSZ)
		dumpTraceScenario(scenario)

		t.Fatalf("[DiffFuzz] SSZ mismatch => bridged vs fastssz\n"+
			"common prefix length: %d\n"+
			"bridged-len=%d fastssz-len=%d\n"+
			"bridged remainder: %X\n"+
			"fastssz remainder:  %X",
			len(prefix), len(outF1), len(outF2), outF1[len(prefix):], outF2[len(prefix):])
		return false
	}

	return true
}

func marshalAsFastssz(v any) ([]byte, error) {
	fsObj, ok := v.(Object)
	if !ok {
		return nil, fmt.Errorf("marshalAsFastssz: not a fastssz type => %T", v)
	}
	return fsObj.MarshalSSZ()
}

func bridgeValue(v reflect.Value) (any, error) {
	if !v.IsValid() {
		return nil, nil
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return zeroForPointerType(v.Type()), nil
		}
		if isUint256Type(v.Type()) {
			ptr, ok := v.Interface().(*uint256.Int)
			if !ok {
				return nil, fmt.Errorf("not *uint256.Int")
			}
			return convertUint256ToByte32(ptr), nil
		}
		return bridgeValue(v.Elem())

	case reflect.Uint8: // byte
		return uint8(v.Uint()), nil

	case reflect.Bool:
		return v.Bool(), nil

	case reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint, reflect.Int, reflect.Int32, reflect.Int64:
		return v.Interface(), nil

	case reflect.Struct:
		if isUint256Type(v.Type()) {
			var uint256Val *uint256.Int
			if v.Type().Kind() != reflect.Ptr && v.CanAddr() {
				var ok bool
				uint256Val, ok = v.Addr().Interface().(*uint256.Int)
				if !ok {
					return nil, fmt.Errorf("failed to assert address of type %s to *uint256.Int", v.Type())
				}
			} else {
				var ok bool
				uint256Val, ok = v.Interface().(*uint256.Int)
				if !ok {
					return nil, fmt.Errorf("failed to assert value of type %s to *uint256.Int", v.Type())
				}
			}
			return convertUint256ToByte32(uint256Val), nil
		}

		return bridgeStructValue(v)

	case reflect.Slice:
		return bridgeSlice(v)

	case reflect.Array:
		return bridgeArray(v)

	default:
		return v.Interface(), nil
	}
}

func zeroForPointerType(ptrType reflect.Type) any {
	elem := ptrType.Elem()
	switch elem.Kind() {
	case reflect.Bool:
		return false
	case reflect.Uint8:
		return uint8(0)
	case reflect.Uint16:
		return uint16(0)
	case reflect.Uint32:
		return uint32(0)
	case reflect.Uint64:
		return uint64(0)
	default:
		return nil
	}
}

func bridgeStructValue(v reflect.Value) (any, error) {
	fastObj, err := newFastsszObjectFromKaralabeType(v.Type())
	if err != nil {
		return nil, err
	}
	fastVal := reflect.ValueOf(fastObj).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fieldName := t.Field(i).Name
		karField := v.Field(i)
		fastField := fastVal.FieldByName(fieldName)

		if !fastField.IsValid() {
			return nil, fmt.Errorf("field %s not found in fastssz type", fieldName)
		}

		converted, err := bridgeValue(karField)
		if err != nil {
			return nil, fmt.Errorf("error bridging field %s: %w", fieldName, err)
		}

		if reflect.TypeOf(converted) != fastField.Type() {
			if reflect.ValueOf(converted).Type().ConvertibleTo(fastField.Type()) {
				converted = reflect.ValueOf(converted).Convert(fastField.Type()).Interface()
			} else {
				return nil, fmt.Errorf("cannot convert field %s from %T to %s", fieldName, converted, fastField.Type())
			}
		}
		fastField.Set(reflect.ValueOf(converted))
	}
	return fastObj, nil
}

func bridgeSlice(v reflect.Value) (any, error) {
	n := v.Len()

	bridgedElems := make([]reflect.Value, n)
	for i := 0; i < n; i++ {
		bridged, err := bridgeValue(v.Index(i))
		if err != nil {
			return nil, err
		}
		bridgedElems[i] = reflect.ValueOf(bridged)
	}

	var elemType reflect.Type
	if n > 0 {
		elemType = bridgedElems[0].Type()
	} else {

		elemType = v.Type().Elem()
	}

	outSliceType := reflect.SliceOf(elemType)
	outSliceVal := reflect.MakeSlice(outSliceType, 0, n)
	for _, bv := range bridgedElems {
		if !bv.Type().ConvertibleTo(elemType) {
			return nil, fmt.Errorf("slice element type mismatch: %v not convertible to %v",
				bv.Type(), elemType)
		}
		outSliceVal = reflect.Append(outSliceVal, bv.Convert(elemType))
	}

	return outSliceVal.Interface(), nil
}

func bridgeArray(v reflect.Value) (any, error) {
	arrLen := v.Len()
	elemType := v.Type().Elem()

	bridgedElems := make([]reflect.Value, arrLen)
	for i := 0; i < arrLen; i++ {
		bridged, err := bridgeValue(v.Index(i))
		if err != nil {
			return nil, err
		}
		bridgedElems[i] = reflect.ValueOf(bridged)
	}

	outArrType := reflect.ArrayOf(arrLen, elemType)

	if arrLen > 0 {
		finalElemType := bridgedElems[0].Type()
		outArrType = reflect.ArrayOf(arrLen, finalElemType)
	}

	outArrVal := reflect.New(outArrType).Elem()
	for i := 0; i < arrLen; i++ {
		bv := bridgedElems[i]
		if !bv.Type().ConvertibleTo(outArrType.Elem()) {
			return nil, fmt.Errorf("element %d not convertible from %v to %v",
				i, bv.Type(), outArrType.Elem())
		}
		outArrVal.Index(i).Set(bv.Convert(outArrType.Elem()))
	}

	return outArrVal.Interface(), nil
}

func isUint256Type(t reflect.Type) bool {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	return (t.PkgPath() == "github.com/holiman/uint256" && t.Name() == "Int")
}

func convertUint256ToByte32(x *uint256.Int) [32]byte {
	var out [32]byte
	if x == nil {
		return out
	}
	out = x.Bytes32()
	return out
}

type traceStep struct {
	Method string `json:"method"`
	// ObjType  string `json:"obj_type"`
	Leftover int `json:"leftover"`
}

type traceScenario struct {
	InputHex string      `json:"input_hex"`
	Steps    []traceStep `json:"steps"`
}

type traceManager struct {
	mu    sync.Mutex
	steps []traceStep
}

func NewTraceManager() *traceManager {
	return &traceManager{}
}

func (tm *traceManager) recordStep(method string, leftover int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.steps = append(tm.steps, traceStep{
		Method: method,
		// ObjType: objType,
		Leftover: leftover,
	})
}

func (tm *traceManager) buildScenario(input []byte) traceScenario {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	copied := make([]traceStep, len(tm.steps))
	copy(copied, tm.steps)

	return traceScenario{
		InputHex: hex.EncodeToString(input),
		Steps:    copied,
	}
}

func dumpTraceScenario(s traceScenario) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal scenario: %v\n", err)
		return
	}
	filename := fmt.Sprintf("crash_%d.json", time.Now().UnixNano())
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write scenario: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Crash scenario dumped to %s\n", filename)
	}
}
