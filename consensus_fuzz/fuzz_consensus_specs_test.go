// fuzz_consensus_specs.go
//go:build gofuzz
// +build gofuzz

package consensus_fuzz

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

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
		var valid bool

		// (a) Try stream-based decode/encode roundtrip
		{
			obj := T(new(U))
			if decodeStreamRoundtrip(t, inSSZ, obj) {
				// If decode/encode succeeded, run final checks
				finalChecks(t, inSSZ, obj)

				// Do differential fuzz check
				if differentialCheckFastssz[T, U](t, inSSZ) {
					valid = true
				}
			}
		}

		// (b) If not valid yet, try buffer-based decode/encode roundtrip
		if !valid {
			obj2 := T(new(U))
			if decodeBufferRoundtrip(t, inSSZ, obj2) {
				finalChecks(t, inSSZ, obj2)

				// Do differential fuzz check
				if differentialCheckFastssz[T, U](t, inSSZ) {
					valid = true
				}
			}
		}

		// (c) If valid => do extra stateful/crossFork checks (handleValidCase)
		if valid {
			handleValidCase[T, U](t, inSSZ)
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
func decodeStreamRoundtrip[T newableObject[U], U any](t *testing.T, inSSZ []byte, obj T) bool {
	if err := kssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
		// decode false -> roundtrip impossible
		return false
	}

	// Stream decoder succeeded, make sure it re-encodes correctly and
	// that the buffer decoder also succeeds parsing
	blob := new(bytes.Buffer)
	if err := kssz.EncodeToStreamOnFork(blob, obj, kssz.ForkFuture); err != nil {
		t.Fatalf("failed to re-encode stream: %v", err)
	}

	if !bytes.Equal(blob.Bytes(), inSSZ) {
		prefix := commonPrefix(blob.Bytes(), inSSZ)
		t.Fatalf("re-encoded stream mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			blob, inSSZ, len(prefix), blob.Bytes()[len(prefix):], inSSZ[len(prefix):])
	}

	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode buffer: %v", err)
	}
	return true
}

// decodeBufferRoundtrip tries decoding the SSZ bytes in buffer mode,
// then re-encodes them in buffer mode again, compares, and returns true if they match.
func decodeBufferRoundtrip[T newableObject[U], U any](t *testing.T, inSSZ []byte, obj T) bool {
	// Try the buffer encoder/decoder
	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		return false
	}

	// Buffer decoder succeeded, make sure it re-encodes correctly and
	// that the stream decoder also succeeds parsing
	bin := make([]byte, kssz.SizeOnFork(obj, kssz.ForkFuture))
	if err := kssz.EncodeToBytesOnFork(bin, obj, kssz.ForkFuture); err != nil {
		t.Fatalf("failed to re-encode buffer: %v", err)
	}

	if !bytes.Equal(bin, inSSZ) {
		prefix := commonPrefix(bin, inSSZ)
		t.Fatalf("re-encoded buffer mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			bin, inSSZ, len(prefix), bin[len(prefix):], inSSZ[len(prefix):])
	}

	if err := kssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode stream: %v", err)
	}
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

func handleValidCase[T newableObject[U], U any](t *testing.T, inSSZ []byte) {

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

	if err := kssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode stream into used object: %v", err)
	}

	blob := new(bytes.Buffer)
	if err := kssz.EncodeToStreamOnFork(blob, obj, kssz.ForkFuture); err != nil {
		t.Fatalf("failed to re-encode stream from used object: %v", err)
	}

	if !bytes.Equal(blob.Bytes(), inSSZ) {
		prefix := commonPrefix(blob.Bytes(), inSSZ)
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
	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode buffer into used object: %v", err)
	}
	bin := make([]byte, kssz.SizeOnFork(obj, kssz.ForkFuture))
	if err := kssz.EncodeToBytesOnFork(bin, obj, kssz.ForkFuture); err != nil {
		t.Fatalf("failed to re-encode buffer from used object: %v", err)
	}
	if !bytes.Equal(bin, inSSZ) {
		prefix := commonPrefix(bin, inSSZ)
		t.Fatalf("re-encoded buffer from used object mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			bin, inSSZ, len(prefix), bin[len(prefix):], inSSZ[len(prefix):])
	}

	finalChecks(t, inSSZ, obj)

	// cross fork decode
	crossForkCheck(t, inSSZ, obj)
}

// crossForkCheck : decode 'inSSZ' for all known forks => coverage
func crossForkCheck[T newableObject[U], U any](t *testing.T, inSSZ []byte, obj T) {
	for forkName, forkVal := range kssz.ForkMapping {
		// skip unknown => or keep it if you want
		if forkVal == kssz.ForkUnknown {
			continue
		}

		if cl, ok := any(obj).(interface{ ClearSSZ() }); ok {
			cl.ClearSSZ()
		}

		if err := kssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), forkVal); err == nil {
			// success => re-encode just for coverage
			sz2 := kssz.SizeOnFork(obj, forkVal)
			out := make([]byte, sz2)
			if err2 := kssz.EncodeToBytesOnFork(out, obj, forkVal); err2 == nil {
				// t.Logf("[crossFork] fork=%s => decode+encode ok (size=%d)", forkName, sz2)
				continue
			} else {
				t.Logf("[crossFork] fork=%s => re-encode fail: %v", forkName, err2)
			}
		} else {
			t.Logf("[crossFork] fork=%s => decode fail: %v", forkName, err)
		}
	}
}

type Object interface {
	fssz.Marshaler
	fssz.Unmarshaler
	fssz.HashRoot
}

func newFastsszObject[T any]() (Object, error) {
	var zero T
	rt := reflect.TypeOf(zero)

	if rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}

	pkgPath := rt.PkgPath()
	typeName := rt.Name()

	if pkgPath == "github.com/KindKillerwhale/sszfuzzer/types/sszgen" {
		switch typeName {
		case "AggregateAndProof":
			return &fastssz.AggregateAndProof{}, nil

		case "AttestationData":
			return &fastssz.AttestationData{}, nil

		case "AttestationDataVariation1":
			return &fastssz.AttestationDataVariation1{}, nil

		case "AttestationDataVariation2":
			return &fastssz.AttestationDataVariation2{}, nil

		case "AttestationDataVariation3":
			return &fastssz.AttestationDataVariation3{}, nil

		case "Attestation":
			return &fastssz.Attestation{}, nil

		case "AttestationVariation1":
			return &fastssz.AttestationVariation1{}, nil

		case "AttestationVariation2":
			return &fastssz.AttestationVariation2{}, nil

		case "AttestationVariation3":
			return &fastssz.AttestationVariation3{}, nil

		case "AttesterSlashing":
			return &fastssz.AttesterSlashing{}, nil

		case "BeaconBlockBodyAltair":
			return &fastssz.BeaconBlockBodyAltair{}, nil

		case "BeaconBlockBodyBellatrix":
			return &fastssz.BeaconBlockBodyBellatrix{}, nil

		case "BeaconBlockBodyCapella":
			return &fastssz.BeaconBlockBodyCapella{}, nil

		case "BeaconBlockBodyDeneb":
			return &fastssz.BeaconBlockBodyDeneb{}, nil

		case "BeaconBlockBodyMonolith":
			return &fastssz.BeaconBlockBodyMonolith{}, nil

		case "BeaconBlockBody":
			return &fastssz.BeaconBlockBody{}, nil

		case "BeaconBlockHeader":
			return &fastssz.BeaconBlockHeader{}, nil

		case "BeaconBlock":
			return &fastssz.BeaconBlock{}, nil

		case "BeaconStateAltair":
			return &fastssz.BeaconStateAltair{}, nil

		case "BeaconStateBellatrix":
			return &fastssz.BeaconStateBellatrix{}, nil

		case "BeaconStateCapella":
			return &fastssz.BeaconStateCapella{}, nil

		case "BeaconStateDeneb":
			return &fastssz.BeaconStateDeneb{}, nil

		case "BeaconStateMonolith":
			return &fastssz.BeaconStateMonolith{}, nil

		case "BeaconState":
			return &fastssz.BeaconState{}, nil

		case "BitsStructMonolith":
			return &fastssz.BitsStructMonolith{}, nil

		case "BitsStruct":
			return &fastssz.BitsStruct{}, nil

		case "BLSToExecutionChange":
			return &fastssz.BLSToExecutionChange{}, nil

		case "Checkpoint":
			return &fastssz.Checkpoint{}, nil

		case "DepositData":
			return &fastssz.DepositData{}, nil

		case "DepositMessage":
			return &fastssz.DepositMessage{}, nil

		case "Deposit":
			return &fastssz.Deposit{}, nil

		case "Eth1Block":
			return &fastssz.Eth1Block{}, nil

		case "Eth1Data":
			return &fastssz.Eth1Data{}, nil

		case "ExecutionPayloadCapella":
			return &fastssz.ExecutionPayloadCapella{}, nil

		case "ExecutionPayloadDeneb":
			return &fastssz.ExecutionPayloadDeneb{}, nil

		case "ExecutionPayloadHeaderCapella":
			return &fastssz.ExecutionPayloadHeaderCapella{}, nil

		case "ExecutionPayloadHeaderDeneb":
			return &fastssz.ExecutionPayloadHeaderDeneb{}, nil

		case "ExecutionPayloadHeaderMonolith":
			return &fastssz.ExecutionPayloadHeaderMonolith{}, nil

		case "ExecutionPayloadHeader":
			return &fastssz.ExecutionPayloadHeader{}, nil

		case "ExecutionPayloadMonolith2":
			return &fastssz.ExecutionPayloadMonolith2{}, nil

		case "ExecutionPayloadMonolith":
			return &fastssz.ExecutionPayloadMonolith{}, nil

		case "ExecutionPayload":
			return &fastssz.ExecutionPayload{}, nil

		case "ExecutionPayloadVariation":
			return &fastssz.ExecutionPayloadVariation{}, nil

		case "FixedTestStructMonolith":
			return &fastssz.FixedTestStructMonolith{}, nil

		case "FixedTestStruct":
			return &fastssz.FixedTestStruct{}, nil

		case "Fork":
			return &fastssz.Fork{}, nil

		case "HistoricalBatch":
			return &fastssz.HistoricalBatch{}, nil

		case "HistoricalBatchVariation":
			return &fastssz.HistoricalBatchVariation{}, nil

		case "HistoricalSummary":
			return &fastssz.HistoricalSummary{}, nil

		case "IndexedAttestation":
			return &fastssz.IndexedAttestation{}, nil

		case "PendingAttestation":
			return &fastssz.PendingAttestation{}, nil

		case "ProposerSlashing":
			return &fastssz.ProposerSlashing{}, nil

		case "SignedBeaconBlockHeader":
			return &fastssz.SignedBeaconBlockHeader{}, nil

		case "SignedBLSToExecutionChange":
			return &fastssz.SignedBLSToExecutionChange{}, nil

		case "SignedVoluntaryExit":
			return &fastssz.SignedVoluntaryExit{}, nil

		case "SingleFieldTestStructMonolith":
			return &fastssz.SingleFieldTestStructMonolith{}, nil

		case "SingleFieldTestStruct":
			return &fastssz.SingleFieldTestStruct{}, nil

		case "SmallTestStructMonolith":
			return &fastssz.SmallTestStructMonolith{}, nil

		case "SmallTestStruct":
			return &fastssz.SmallTestStruct{}, nil

		case "SyncAggregate":
			return &fastssz.SyncAggregate{}, nil

		case "SyncCommittee":
			return &fastssz.SyncCommittee{}, nil

		case "ValidatorMonolith":
			return &fastssz.ValidatorMonolith{}, nil

		case "Validator":
			return &fastssz.Validator{}, nil

		case "VoluntaryExit":
			return &fastssz.VoluntaryExit{}, nil

		case "Withdrawal":
			return &fastssz.Withdrawal{}, nil

		case "WithdrawalVariation":
			return &fastssz.WithdrawalVariation{}, nil

		default:
			return nil, fmt.Errorf("unmapped T => %s.%s", pkgPath, typeName)
		}
	}
	return nil, fmt.Errorf("unmapped T => %s.%s", pkgPath, typeName)
}

func differentialCheckFastssz[T newableObject[U], U any](t *testing.T, inSSZ []byte) bool {
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

	// 3) karalabe -> fastssz Bridging
	bridged, err := BridgeKaralabeToFastssz(objKaralabe)
	if err != nil {
		t.Fatalf("[DiffFuzz] bridging karalabe->fastssz error: %v\n", err)
		return false
	}

	// 3) bridged vs objFastssz
	diff := cmp.Diff(bridged, objFastssz)
	if diff != "" {
		t.Fatalf("[DiffFuzz] Decoded object mismatch => (karalabe->bridged) vs fastssz\nDiff:\n%s", diff)
		return false
	}

	// 4) Re-encode with fastssz (bridged vs direct)
	outF1, err1 := marshalAsFastssz(bridged)
	if err1 != nil {
		t.Fatalf("[DiffFuzz] fail to re-encode bridged (fastssz): %v", err1)
		return false
	}
	outF2, err2 := objFastssz.MarshalSSZ()
	if err2 != nil {
		t.Fatalf("[DiffFuzz] fastssz re-encode fail: %v", err2)
		return false
	}

	// 5) Compare re-encoded bytes
	if !bytes.Equal(outF1, outF2) {
		prefix := commonPrefix(outF1, outF2)
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

func BridgeKaralabeToFastssz(k any) (any, error) {
	if k == nil {
		return nil, nil
	}
	return bridgeValue(reflect.ValueOf(k))
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
		return bridgeValue(v.Elem())

	case reflect.Uint8: // byte
		return uint8(v.Uint()), nil

	case reflect.Bool:
		return v.Bool(), nil

	case reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint, reflect.Int, reflect.Int32, reflect.Int64:
		return v.Interface(), nil

	case reflect.Struct:
		if isUint256Type(v.Type()) {
			iFace := v.Interface()
			if x, ok := iFace.(*uint256.Int); ok {
				return convertUint256ToByte32(x), nil
			}
			arr := convertUint256ToByte32(iFace.(*uint256.Int))
			return arr, nil
		}
		return bridgeStruct(v)

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

func bridgeStruct(v reflect.Value) (any, error) {
	outMap := make(map[string]any)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fName := t.Field(i).Name
		fieldVal := v.Field(i)
		bridged, err := bridgeValue(fieldVal)
		if err != nil {
			return nil, fmt.Errorf("struct field %s bridging error: %w", fName, err)
		}
		outMap[fName] = bridged
	}
	return outMap, nil
}

func bridgeSlice(v reflect.Value) (any, error) {
	length := v.Len()
	out := make([]any, 0, length)
	for i := 0; i < length; i++ {
		bridgedElem, err := bridgeValue(v.Index(i))
		if err != nil {
			return nil, err
		}
		out = append(out, bridgedElem)
	}
	return out, nil
}

func bridgeArray(v reflect.Value) (any, error) {
	arrLen := v.Len()
	elemType := v.Type().Elem()

	if elemType.Kind() == reflect.Array {
		out := make([]any, arrLen)
		for i := 0; i < arrLen; i++ {
			bridgedElem, err := bridgeArray(v.Index(i))
			if err != nil {
				return nil, err
			}
			out[i] = bridgedElem
		}
		return out, nil
	}

	out := make([]any, 0, arrLen)
	for i := 0; i < arrLen; i++ {
		bridgedElem, err := bridgeValue(v.Index(i))
		if err != nil {
			return nil, err
		}
		out = append(out, bridgedElem)
	}
	return out, nil
}

func isUint256Type(t reflect.Type) bool {
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
