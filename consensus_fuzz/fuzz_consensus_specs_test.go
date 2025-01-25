// fuzz_consensus_specs.go
//go:build gofuzz
// +build gofuzz

package consensus_fuzz

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/snappy"
	"github.com/karalabe/ssz"

	// Ethereum consensus spec types (Attestation, BeaconBlock, etc.)
	// types "github.com/karalabe/ssz/tests/testtypes/consensus-spec-tests"
	types "github.com/KindKillerwhale/sszfuzzer/types/sszgen"
)

var (
	// consensusSpecTestsRoot is the folder where the consensus ssz tests are located.
	// It depends on the path of the binary.
	// Setting the path as a temporary measure
	consensusSpecTestsRoot = filepath.Join("..", "..", "corpus", "consensus-spec-tests", "tests", "mainnet")
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
	ssz.Object
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
	// 1) Collect corpus from fork directories
	valids := collectValidCorpus[T, U](f, kind, consensusSpecTestsRoot)

	// 2) Actual fuzz logic
	f.Fuzz(func(t *testing.T, inSSZ []byte) {
		var valid bool

		// (a) Try stream-based decode/encode roundtrip
		{
			obj := T(new(U))
			if decodeStreamRoundtrip(t, inSSZ, obj) {
				// If decode/encode succeeded, run final checks
				finalChecks(t, inSSZ, obj)
				valid = true
			}
		}

		// (b) If not valid yet, try buffer-based decode/encode roundtrip
		if !valid {
			obj2 := T(new(U))
			if decodeBufferRoundtrip(t, inSSZ, obj2) {
				finalChecks(t, inSSZ, obj2)
				valid = true
			}
		}

		// (c) If valid => do extra stateful/crossFork checks (handleValidCase)
		if valid && len(valids) > 0 {
			handleValidCase[T, U](t, inSSZ, valids)
		}
	})
}

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
			if err := ssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), ssz.ForkFuture); err == nil {
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

// decodeStreamRoundtrip tries decoding the SSZ bytes in streaming mode,
// then re-encodes them in streaming mode again, compares, and returns true if they match.
func decodeStreamRoundtrip[T newableObject[U], U any](t *testing.T, inSSZ []byte, obj T) bool {
	if err := ssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), ssz.ForkFuture); err != nil {
		// decode false -> roundtrip impossible
		return false
	}

	// Stream decoder succeeded, make sure it re-encodes correctly and
	// that the buffer decoder also succeeds parsing
	blob := new(bytes.Buffer)
	if err := ssz.EncodeToStreamOnFork(blob, obj, ssz.ForkFuture); err != nil {
		t.Fatalf("failed to re-encode stream: %v", err)
	}

	if !bytes.Equal(blob.Bytes(), inSSZ) {
		prefix := commonPrefix(blob.Bytes(), inSSZ)
		t.Fatalf("re-encoded stream mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			blob, inSSZ, len(prefix), blob.Bytes()[len(prefix):], inSSZ[len(prefix):])
	}

	if err := ssz.DecodeFromBytesOnFork(inSSZ, obj, ssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode buffer: %v", err)
	}
	return true
}

// decodeBufferRoundtrip tries decoding the SSZ bytes in buffer mode,
// then re-encodes them in buffer mode again, compares, and returns true if they match.
func decodeBufferRoundtrip[T newableObject[U], U any](t *testing.T, inSSZ []byte, obj T) bool {
	// Try the buffer encoder/decoder
	if err := ssz.DecodeFromBytesOnFork(inSSZ, obj, ssz.ForkFuture); err != nil {
		return false
	}

	// Buffer decoder succeeded, make sure it re-encodes correctly and
	// that the stream decoder also succeeds parsing
	bin := make([]byte, ssz.SizeOnFork(obj, ssz.ForkFuture))
	if err := ssz.EncodeToBytesOnFork(bin, obj, ssz.ForkFuture); err != nil {
		t.Fatalf("failed to re-encode buffer: %v", err)
	}

	if !bytes.Equal(bin, inSSZ) {
		prefix := commonPrefix(bin, inSSZ)
		t.Fatalf("re-encoded buffer mismatch: have %x, want %x, common prefix %d, have left %x, want left %x",
			bin, inSSZ, len(prefix), bin[len(prefix):], inSSZ[len(prefix):])
	}

	if err := ssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), ssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode stream: %v", err)
	}
	return true
}

// finalChecks verifies that concurrent vs sequential merkle root match,
// and that size matches the input length, etc.
func finalChecks[T newableObject[U], U any](t *testing.T, inSSZ []byte, obj T) {
	hashSeq := ssz.HashSequentialOnFork(obj, ssz.ForkFuture)
	hashConc := ssz.HashConcurrentOnFork(obj, ssz.ForkFuture)

	if hashSeq != hashConc {
		t.Fatalf("sequential/concurrent hash mismatch: sequencial %x, concurrent %x", hashSeq, hashConc)
	}

	sz := ssz.SizeOnFork(obj, ssz.ForkFuture)
	if sz != uint32(len(inSSZ)) {
		t.Fatalf("reported/generated size mismatch: reported %v, generated %v", sz, len(inSSZ))
	}
}

// --------------------------------------------------------
// handleValidCase (stateful leftover decode, crossForkCheck)
// --------------------------------------------------------

func handleValidCase[T newableObject[U], U any](t *testing.T, inSSZ []byte, valids [][]byte) {
	// pick random from corpus
	vSSZ := valids[rand.Intn(len(valids))]

	// Try the stream encoder/decoder into a prepped object
	obj := T(new(U))

	if cl, ok := any(obj).(interface{ ClearSSZ() }); ok {
		// t.Logf("===> ClearSSZ() is found and will be called!")
		cl.ClearSSZ()
	} else {
		t.Errorf("===> ClearSSZ() not found on this type.")
	}

	if err := ssz.DecodeFromBytesOnFork(vSSZ, obj, ssz.ForkFuture); err != nil {
		panic(err) // we've already decoded this, cannot fail
	}

	if err := ssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), ssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode stream into used object: %v", err)
	}

	blob := new(bytes.Buffer)
	if err := ssz.EncodeToStreamOnFork(blob, obj, ssz.ForkFuture); err != nil {
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

	if err := ssz.DecodeFromBytesOnFork(vSSZ, obj, ssz.ForkFuture); err != nil {
		panic(err) // we've already decoded this, cannot fail
	}
	if err := ssz.DecodeFromBytesOnFork(inSSZ, obj, ssz.ForkFuture); err != nil {
		t.Fatalf("failed to decode buffer into used object: %v", err)
	}
	bin := make([]byte, ssz.SizeOnFork(obj, ssz.ForkFuture))
	if err := ssz.EncodeToBytesOnFork(bin, obj, ssz.ForkFuture); err != nil {
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
	for forkName, forkVal := range ssz.ForkMapping {
		// skip unknown => or keep it if you want
		if forkVal == ssz.ForkUnknown {
			continue
		}

		if cl, ok := any(obj).(interface{ ClearSSZ() }); ok {
			cl.ClearSSZ()
		}

		if err := ssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), forkVal); err == nil {
			// success => re-encode just for coverage
			sz2 := ssz.SizeOnFork(obj, forkVal)
			out := make([]byte, sz2)
			if err2 := ssz.EncodeToBytesOnFork(out, obj, forkVal); err2 == nil {
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
