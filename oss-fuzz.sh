#!/bin/bash -eu

coverpkg="github.com/KindKillerwhale/sszfuzzer/..."
SANITIZER="address"
CXX="clang++"
CXXFLAGS="-O1 -g"
LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
CC=clang

BASE_OUT="$GOPATH/src/github.com/KindKillerwhale/sszfuzzer/consensus_fuzz/fuzzer"

function coverbuild {
  path=$1
  function=$2
  fuzzer=$3
  tags=""

  if [[ $#  -eq 4 ]]; then
    tags="-tags $4"
  fi
  cd $path
  fuzzed_package=`pwd | rev | cut -d'/' -f 1 | rev`
  cp $GOPATH/ossfuzz_coverage_runner.go ./"${function,,}".go
  sed -i -e 's/FuzzFunction/'$function'/' ./"${function,,}".go
  sed -i -e 's/mypackagebeingfuzzed/'$fuzzed_package'/' ./"${function,,}".go
  sed -i -e 's/TestFuzzCorpus/Test'$function'Corpus/' ./"${function,,}".go

cat << DOG > $BASE_OUT/$fuzzer
#/bin/sh

  cd $BASE_OUT/$path
  go test -run Test${function}Corpus -v $tags -coverprofile \$1 -coverpkg $coverpkg

DOG

  chmod +x $BASE_OUT/$fuzzer
  #echo "Built script $OUT/$fuzzer"
  #cat $OUT/$fuzzer
  cd -
}


function compile_fuzzer() {
  package=$1
  function=$2
  fuzzer=$3
  file=$4

  path=$GOPATH/src/$package
  outdir=$BASE_OUT/$fuzzer

  echo "Building $fuzzer in $path"
  cd $path

  go mod tidy
  go get github.com/holiman/gofuzz-shim/testing

  if [[ $SANITIZER == *coverage* ]]; then
    coverbuild $path $function $fuzzer $coverpkg
  else
    gofuzz-shim --func $function --package $package -f $file -o $fuzzer.a
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o ./$fuzzer
  fi

  mkdir -p $outdir

  mv "$fuzzer" "$fuzzer.a" "$outdir" 2>/dev/null || true
  mv main_*.go *.h *_fuzz.go "$outdir" 2>/dev/null || true
  cd -

  echo "Built fuzzer => $outdir/$fuzzer"
}

mkdir -p $BASE_OUT
go install github.com/holiman/gofuzz-shim@latest
repo=$GOPATH/src/github.com/KindKillerwhale/sszfuzzer

# AggregateAndProof
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsAggregateAndProof \
  fuzz_consensus_specs_aggregate_and_proof \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Attestation
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsAttestation \
  fuzz_consensus_specs_attestation \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# AttestationData
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsAttestationData \
  fuzz_consensus_specs_attestation_data \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# AttesterSlashing
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsAttesterSlashing \
  fuzz_consensus_specs_attester_slashing \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlock
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlock \
  fuzz_consensus_specs_beacon_block \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlockBody
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlockBody \
  fuzz_consensus_specs_beacon_block_body \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlockBodyAltair
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlockBodyAltair \
  fuzz_consensus_specs_beacon_block_body_altair \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlockBodyBellatrix
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlockBodyBellatrix \
  fuzz_consensus_specs_beacon_block_body_bellatrix \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlockBodyCapella
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlockBodyCapella \
  fuzz_consensus_specs_beacon_block_body_capella \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlockBodyDeneb
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlockBodyDeneb \
  fuzz_consensus_specs_beacon_block_body_deneb \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlockHeader
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlockHeader \
  fuzz_consensus_specs_beacon_block_header \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconState
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconState \
  fuzz_consensus_specs_beacon_state \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconStateAltair
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconStateAltair \
  fuzz_consensus_specs_beacon_state_altair \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconStateBellatrix
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconStateBellatrix \
  fuzz_consensus_specs_beacon_state_bellatrix \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconStateCapella
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconStateCapella \
  fuzz_consensus_specs_beacon_state_capella \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconStateDeneb
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconStateDeneb \
  fuzz_consensus_specs_beacon_state_deneb \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BLSToExecutionChange
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBLSToExecutionChange \
  fuzz_consensus_specs_bls_to_execution_change \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Checkpoint
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsCheckpoint \
  fuzz_consensus_specs_checkpoint \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Deposit
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsDeposit \
  fuzz_consensus_specs_deposit \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# DepositData
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsDepositData \
  fuzz_consensus_specs_deposit_data \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# DepositMessage
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsDepositMessage \
  fuzz_consensus_specs_deposit_message \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Eth1Block
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsEth1Block \
  fuzz_consensus_specs_eth1_block \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Eth1Data
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsEth1Data \
  fuzz_consensus_specs_eth1_data \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayload
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayload \
  fuzz_consensus_specs_execution_payload \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadCapella
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadCapella \
  fuzz_consensus_specs_execution_payload_capella \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadDeneb
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadDeneb \
  fuzz_consensus_specs_execution_payload_deneb \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadHeader
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadHeader \
  fuzz_consensus_specs_execution_payload_header \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadHeaderCapella
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadHeaderCapella \
  fuzz_consensus_specs_execution_payload_header_capella \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadHeaderDeneb
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadHeaderDeneb \
  fuzz_consensus_specs_execution_payload_header_deneb \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Fork
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsFork \
  fuzz_consensus_specs_fork \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# HistoricalBatch
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsHistoricalBatch \
  fuzz_consensus_specs_historical_batch \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# HistoricalSummary
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsHistoricalSummary \
  fuzz_consensus_specs_historical_summary \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# IndexedAttestation
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsIndexedAttestation \
  fuzz_consensus_specs_indexed_attestation \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# PendingAttestation
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsPendingAttestation \
  fuzz_consensus_specs_pending_attestation \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ProposerSlashing
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsProposerSlashing \
  fuzz_consensus_specs_proposer_slashing \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# SignedBeaconBlockHeader
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsSignedBeaconBlockHeader \
  fuzz_consensus_specs_signed_beacon_block_header \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# SignedBLSToExecutionChange
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsSignedBLSToExecutionChange \
  fuzz_consensus_specs_signed_bls_to_execution_change \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# SignedVoluntaryExit
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsSignedVoluntaryExit \
  fuzz_consensus_specs_signed_voluntary_exit \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# SyncAggregate
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsSyncAggregate \
  fuzz_consensus_specs_sync_aggregate \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# SyncCommittee
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsSyncCommittee \
  fuzz_consensus_specs_sync_committee \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Validator
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsValidator \
  fuzz_consensus_specs_validator \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# VoluntaryExit
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsVoluntaryExit \
  fuzz_consensus_specs_voluntary_exit \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# Withdrawal
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsWithdrawal \
  fuzz_consensus_specs_withdrawal \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconBlockBodyMonolith
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconBlockBodyMonolith \
  fuzz_consensus_specs_beacon_block_body_monolith \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# BeaconStateMonolith
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsBeaconStateMonolith \
  fuzz_consensus_specs_beacon_state_monolith \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadMonolith
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadMonolith \
  fuzz_consensus_specs_execution_payload_monolith \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadHeaderMonolith
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadHeaderMonolith \
  fuzz_consensus_specs_execution_payload_header_monolith \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# ExecutionPayloadVariation
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsExecutionPayloadVariation \
  fuzz_consensus_specs_execution_payload_variation \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# HistoricalBatchVariation
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsHistoricalBatchVariation \
  fuzz_consensus_specs_historical_batch_variation \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"

# WithdrawalVariation
compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsWithdrawalVariation \
  fuzz_consensus_specs_withdrawal_variation \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"
