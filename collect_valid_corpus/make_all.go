// make_all.go

package main

import "log"

const corpusPath = "../consensus_fuzz/corpus/"

func main() {
	if err := GenerateSeedCorpusAttestation(corpusPath + "fuzz_consensus_specs_attestation_seed_corpus.zip"); err != nil {
		log.Printf("Error: Attestation: %v", err)
	}
	if err := GenerateSeedCorpusSingleFieldTestStruct(corpusPath + "fuzz_consensus_specs_single_field_test_struct_seed_corpus.zip"); err != nil {
		log.Printf("Error: SingleFieldTestStruct: %v", err)
	}
	if err := GenerateSeedCorpusSmallTestStruct(corpusPath + "fuzz_consensus_specs_small_test_struct_seed_corpus.zip"); err != nil {
		log.Printf("Error: SmallTestStruct: %v", err)
	}
	if err := GenerateSeedCorpusFixedTestStruct(corpusPath + "fuzz_consensus_specs_fixed_test_struct_seed_corpus.zip"); err != nil {
		log.Printf("Error: FixedTestStruct: %v", err)
	}
	if err := GenerateSeedCorpusBitsStruct(corpusPath + "fuzz_consensus_specs_bits_struct_seed_corpus.zip"); err != nil {
		log.Printf("Error: BitsStruct: %v", err)
	}
	if err := GenerateSeedCorpusCheckpoint(corpusPath + "fuzz_consensus_specs_checkpoint_seed_corpus.zip"); err != nil {
		log.Printf("Error: Checkpoint: %v", err)
	}
	if err := GenerateSeedCorpusAttestationData(corpusPath + "fuzz_consensus_specs_attestation_data_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttestationData: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlockHeader(corpusPath + "fuzz_consensus_specs_beacon_block_header_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlockHeader: %v", err)
	}
	if err := GenerateSeedCorpusBLSToExecutionChange(corpusPath + "fuzz_consensus_specs_bls_to_execution_change_seed_corpus.zip"); err != nil {
		log.Printf("Error: BLSToExecutionChange: %v", err)
	}
	if err := GenerateSeedCorpusAggregateAndProof(corpusPath + "fuzz_consensus_specs_aggregate_and_proof_seed_corpus.zip"); err != nil {
		log.Printf("Error: AggregateAndProof: %v", err)
	}
	if err := GenerateSeedCorpusDepositData(corpusPath + "fuzz_consensus_specs_deposit_data_seed_corpus.zip"); err != nil {
		log.Printf("Error: DepositData: %v", err)
	}
	if err := GenerateSeedCorpusDepositMessage(corpusPath + "fuzz_consensus_specs_deposit_message_seed_corpus.zip"); err != nil {
		log.Printf("Error: DepositMessage: %v", err)
	}
	if err := GenerateSeedCorpusDeposit(corpusPath + "fuzz_consensus_specs_deposit_seed_corpus.zip"); err != nil {
		log.Printf("Error: Deposit: %v", err)
	}
	if err := GenerateSeedCorpusEth1Block(corpusPath + "fuzz_consensus_specs_eth1_block_seed_corpus.zip"); err != nil {
		log.Printf("Error: Eth1Block: %v", err)
	}
	if err := GenerateSeedCorpusEth1Data(corpusPath + "fuzz_consensus_specs_eth1_data_seed_corpus.zip"); err != nil {
		log.Printf("Error: Eth1Data: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayload(corpusPath + "fuzz_consensus_specs_execution_payload_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayload: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadHeader(corpusPath + "fuzz_consensus_specs_execution_payload_header_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadHeader: %v", err)
	}
	if err := GenerateSeedCorpusFork(corpusPath + "fuzz_consensus_specs_fork_seed_corpus.zip"); err != nil {
		log.Printf("Error: Fork: %v", err)
	}
	if err := GenerateSeedCorpusHistoricalBatch(corpusPath + "fuzz_consensus_specs_historical_batch_seed_corpus.zip"); err != nil {
		log.Printf("Error: HistoricalBatch: %v", err)
	}
	if err := GenerateSeedCorpusHistoricalSummary(corpusPath + "fuzz_consensus_specs_historical_summary_seed_corpus.zip"); err != nil {
		log.Printf("Error: HistoricalSummary: %v", err)
	}
	if err := GenerateSeedCorpusIndexedAttestation(corpusPath + "fuzz_consensus_specs_indexed_attestation_seed_corpus.zip"); err != nil {
		log.Printf("Error: IndexedAttestation: %v", err)
	}
	if err := GenerateSeedCorpusAttesterSlashing(corpusPath + "fuzz_consensus_specs_attester_slashing_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttesterSlashing: %v", err)
	}
	if err := GenerateSeedCorpusPendingAttestation(corpusPath + "fuzz_consensus_specs_pending_attestation_seed_corpus.zip"); err != nil {
		log.Printf("Error: PendingAttestation: %v", err)
	}
	if err := GenerateSeedCorpusSignedBeaconBlockHeader(corpusPath + "fuzz_consensus_specs_signed_beacon_block_header_seed_corpus.zip"); err != nil {
		log.Printf("Error: SignedBeaconBlockHeader: %v", err)
	}
	if err := GenerateSeedCorpusProposerSlashing(corpusPath + "fuzz_consensus_specs_proposer_slashing_seed_corpus.zip"); err != nil {
		log.Printf("Error: ProposerSlashing: %v", err)
	}
	if err := GenerateSeedCorpusSignedBLSToExecutionChange(corpusPath + "fuzz_consensus_specs_signed_bls_to_execution_change_seed_corpus.zip"); err != nil {
		log.Printf("Error: SignedBLSToExecutionChange: %v", err)
	}
	if err := GenerateSeedCorpusSyncAggregate(corpusPath + "fuzz_consensus_specs_sync_aggregate_seed_corpus.zip"); err != nil {
		log.Printf("Error: SyncAggregate: %v", err)
	}
	if err := GenerateSeedCorpusSyncCommittee(corpusPath + "fuzz_consensus_specs_sync_committee_seed_corpus.zip"); err != nil {
		log.Printf("Error: SyncCommittee: %v", err)
	}
	if err := GenerateSeedCorpusVoluntaryExit(corpusPath + "fuzz_consensus_specs_voluntary_exit_seed_corpus.zip"); err != nil {
		log.Printf("Error: VoluntaryExit: %v", err)
	}
	if err := GenerateSeedCorpusSignedVoluntaryExit(corpusPath + "fuzz_consensus_specs_signed_voluntary_exit_seed_corpus.zip"); err != nil {
		log.Printf("Error: SignedVoluntaryExit: %v", err)
	}
	if err := GenerateSeedCorpusValidator(corpusPath + "fuzz_consensus_specs_validator_seed_corpus.zip"); err != nil {
		log.Printf("Error: Validator: %v", err)
	}
	if err := GenerateSeedCorpusWithdrawal(corpusPath + "fuzz_consensus_specs_withdrawal_seed_corpus.zip"); err != nil {
		log.Printf("Error: Withdrawal: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadCapella(corpusPath + "fuzz_consensus_specs_execution_payload_capella_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadCapella: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadHeaderCapella(corpusPath + "fuzz_consensus_specs_execution_payload_header_capella_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadHeaderCapella: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadDeneb(corpusPath + "fuzz_consensus_specs_execution_payload_deneb_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadDeneb: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadHeaderDeneb(corpusPath + "fuzz_consensus_specs_execution_payload_header_deneb_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadHeaderDeneb: %v", err)
	}
	if err := GenerateSeedCorpusBeaconState(corpusPath + "fuzz_consensus_specs_beacon_state_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconState: %v", err)
	}
	if err := GenerateSeedCorpusBeaconStateAltair(corpusPath + "fuzz_consensus_specs_beacon_state_altair_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconStateAltair: %v", err)
	}
	if err := GenerateSeedCorpusBeaconStateBellatrix(corpusPath + "fuzz_consensus_specs_beacon_state_bellatrix_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconStateBellatrix: %v", err)
	}
	if err := GenerateSeedCorpusBeaconStateCapella(corpusPath + "fuzz_consensus_specs_beacon_state_capella_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconStateCapella: %v", err)
	}
	if err := GenerateSeedCorpusBeaconStateDeneb(corpusPath + "fuzz_consensus_specs_beacon_state_deneb_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconStateDeneb: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlockBody(corpusPath + "fuzz_consensus_specs_beacon_block_body_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlockBody: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlockBodyAltair(corpusPath + "fuzz_consensus_specs_beacon_block_body_altair_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlockBodyAltair: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlockBodyBellatrix(corpusPath + "fuzz_consensus_specs_beacon_block_body_bellatrix_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlockBodyBellatrix: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlockBodyCapella(corpusPath + "fuzz_consensus_specs_beacon_block_body_capella_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlockBodyCapella: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlockBodyDeneb(corpusPath + "fuzz_consensus_specs_beacon_block_body_deneb_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlockBodyDeneb: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlock(corpusPath + "fuzz_consensus_specs_beacon_block_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlock: %v", err)
	}
	if err := GenerateSeedCorpusSingleFieldTestStructMonolith(corpusPath + "fuzz_consensus_specs_single_field_test_struct_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: SingleFieldTestStructMonolith: %v", err)
	}
	if err := GenerateSeedCorpusSmallTestStructMonolith(corpusPath + "fuzz_consensus_specs_small_test_struct_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: SmallTestStructMonolith: %v", err)
	}
	if err := GenerateSeedCorpusFixedTestStructMonolith(corpusPath + "fuzz_consensus_specs_fixed_test_struct_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: FixedTestStructMonolith: %v", err)
	}
	if err := GenerateSeedCorpusBitsStructMonolith(corpusPath + "fuzz_consensus_specs_bits_struct_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: BitsStructMonolith: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadMonolith(corpusPath + "fuzz_consensus_specs_execution_payload_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadMonolith: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadMonolith2(corpusPath + "fuzz_consensus_specs_execution_payload_monolith2_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadMonolith2: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadHeaderMonolith(corpusPath + "fuzz_consensus_specs_execution_payload_header_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadHeaderMonolith: %v", err)
	}
	if err := GenerateSeedCorpusBeaconBlockBodyMonolith(corpusPath + "fuzz_consensus_specs_beacon_block_body_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconBlockBodyMonolith: %v", err)
	}
	if err := GenerateSeedCorpusBeaconStateMonolith(corpusPath + "fuzz_consensus_specs_beacon_state_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: BeaconStateMonolith: %v", err)
	}
	if err := GenerateSeedCorpusValidatorMonolith(corpusPath + "fuzz_consensus_specs_validator_monolith_seed_corpus.zip"); err != nil {
		log.Printf("Error: ValidatorMonolith: %v", err)
	}
	if err := GenerateSeedCorpusWithdrawalVariation(corpusPath + "fuzz_consensus_specs_withdrawal_variation_seed_corpus.zip"); err != nil {
		log.Printf("Error: WithdrawalVariation: %v", err)
	}
	if err := GenerateSeedCorpusHistoricalBatchVariation(corpusPath + "fuzz_consensus_specs_historical_batch_variation_seed_corpus.zip"); err != nil {
		log.Printf("Error: HistoricalBatchVariation: %v", err)
	}
	if err := GenerateSeedCorpusExecutionPayloadVariation(corpusPath + "fuzz_consensus_specs_execution_payload_variation_seed_corpus.zip"); err != nil {
		log.Printf("Error: ExecutionPayloadVariation: %v", err)
	}
	if err := GenerateSeedCorpusAttestationVariation1(corpusPath + "fuzz_consensus_specs_attestation_variation1_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttestationVariation1: %v", err)
	}
	if err := GenerateSeedCorpusAttestationVariation2(corpusPath + "fuzz_consensus_specs_attestation_variation2_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttestationVariation2: %v", err)
	}
	if err := GenerateSeedCorpusAttestationVariation3(corpusPath + "fuzz_consensus_specs_attestation_variation3_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttestationVariation3: %v", err)
	}
	if err := GenerateSeedCorpusAttestationDataVariation1(corpusPath + "fuzz_consensus_specs_attestation_data_variation1_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttestationDataVariation1: %v", err)
	}
	if err := GenerateSeedCorpusAttestationDataVariation2(corpusPath + "fuzz_consensus_specs_attestation_data_variation2_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttestationDataVariation2: %v", err)
	}
	if err := GenerateSeedCorpusAttestationDataVariation3(corpusPath + "fuzz_consensus_specs_attestation_data_variation3_seed_corpus.zip"); err != nil {
		log.Printf("Error: AttestationDataVariation3: %v", err)
	}
}
