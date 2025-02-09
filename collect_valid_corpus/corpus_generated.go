package main

import (
	types "github.com/KindKillerwhale/sszfuzzer/types/sszgen"
)

func GenerateSeedCorpusSingleFieldTestStruct(outZip string) error {
	// T = *types.SingleFieldTestStruct, U = types.SingleFieldTestStruct
	// kind = "SingleFieldTestStruct"
	return generateSeedCorpus[*types.SingleFieldTestStruct, types.SingleFieldTestStruct]("SingleFieldTestStruct", outZip)
}

func GenerateSeedCorpusSmallTestStruct(outZip string) error {
	// T = *types.SmallTestStruct, U = types.SmallTestStruct
	// kind = "SmallTestStruct"
	return generateSeedCorpus[*types.SmallTestStruct, types.SmallTestStruct]("SmallTestStruct", outZip)
}

func GenerateSeedCorpusFixedTestStruct(outZip string) error {
	// T = *types.FixedTestStruct, U = types.FixedTestStruct
	// kind = "FixedTestStruct"
	return generateSeedCorpus[*types.FixedTestStruct, types.FixedTestStruct]("FixedTestStruct", outZip)
}

func GenerateSeedCorpusBitsStruct(outZip string) error {
	// T = *types.BitsStruct, U = types.BitsStruct
	// kind = "BitsStruct"
	return generateSeedCorpus[*types.BitsStruct, types.BitsStruct]("BitsStruct", outZip)
}

func GenerateSeedCorpusCheckpoint(outZip string) error {
	// T = *types.Checkpoint, U = types.Checkpoint
	// kind = "Checkpoint"
	return generateSeedCorpus[*types.Checkpoint, types.Checkpoint]("Checkpoint", outZip)
}

func GenerateSeedCorpusAttestationData(outZip string) error {
	// T = *types.AttestationData, U = types.AttestationData
	// kind = "AttestationData"
	return generateSeedCorpus[*types.AttestationData, types.AttestationData]("AttestationData", outZip)
}

func GenerateSeedCorpusBeaconBlockHeader(outZip string) error {
	// T = *types.BeaconBlockHeader, U = types.BeaconBlockHeader
	// kind = "BeaconBlockHeader"
	return generateSeedCorpus[*types.BeaconBlockHeader, types.BeaconBlockHeader]("BeaconBlockHeader", outZip)
}

func GenerateSeedCorpusBLSToExecutionChange(outZip string) error {
	// T = *types.BLSToExecutionChange, U = types.BLSToExecutionChange
	// kind = "BLSToExecutionChange"
	return generateSeedCorpus[*types.BLSToExecutionChange, types.BLSToExecutionChange]("BLSToExecutionChange", outZip)
}

func GenerateSeedCorpusAttestation(outZip string) error {
	// T = *types.Attestation, U = types.Attestation
	// kind = "Attestation"
	return generateSeedCorpus[*types.Attestation, types.Attestation]("Attestation", outZip)
}

func GenerateSeedCorpusAggregateAndProof(outZip string) error {
	// T = *types.AggregateAndProof, U = types.AggregateAndProof
	// kind = "AggregateAndProof"
	return generateSeedCorpus[*types.AggregateAndProof, types.AggregateAndProof]("AggregateAndProof", outZip)
}

func GenerateSeedCorpusDepositData(outZip string) error {
	// T = *types.DepositData, U = types.DepositData
	// kind = "DepositData"
	return generateSeedCorpus[*types.DepositData, types.DepositData]("DepositData", outZip)
}

func GenerateSeedCorpusDepositMessage(outZip string) error {
	// T = *types.DepositMessage, U = types.DepositMessage
	// kind = "DepositMessage"
	return generateSeedCorpus[*types.DepositMessage, types.DepositMessage]("DepositMessage", outZip)
}

func GenerateSeedCorpusDeposit(outZip string) error {
	// T = *types.Deposit, U = types.Deposit
	// kind = "Deposit"
	return generateSeedCorpus[*types.Deposit, types.Deposit]("Deposit", outZip)
}

func GenerateSeedCorpusEth1Block(outZip string) error {
	// T = *types.Eth1Block, U = types.Eth1Block
	// kind = "Eth1Block"
	return generateSeedCorpus[*types.Eth1Block, types.Eth1Block]("Eth1Block", outZip)
}

func GenerateSeedCorpusEth1Data(outZip string) error {
	// T = *types.Eth1Data, U = types.Eth1Data
	// kind = "Eth1Data"
	return generateSeedCorpus[*types.Eth1Data, types.Eth1Data]("Eth1Data", outZip)
}

func GenerateSeedCorpusExecutionPayload(outZip string) error {
	// T = *types.ExecutionPayload, U = types.ExecutionPayload
	// kind = "ExecutionPayload"
	return generateSeedCorpus[*types.ExecutionPayload, types.ExecutionPayload]("ExecutionPayload", outZip)
}

func GenerateSeedCorpusExecutionPayloadHeader(outZip string) error {
	// T = *types.ExecutionPayloadHeader, U = types.ExecutionPayloadHeader
	// kind = "ExecutionPayloadHeader"
	return generateSeedCorpus[*types.ExecutionPayloadHeader, types.ExecutionPayloadHeader]("ExecutionPayloadHeader", outZip)
}

func GenerateSeedCorpusFork(outZip string) error {
	// T = *types.Fork, U = types.Fork
	// kind = "Fork"
	return generateSeedCorpus[*types.Fork, types.Fork]("Fork", outZip)
}

func GenerateSeedCorpusHistoricalBatch(outZip string) error {
	// T = *types.HistoricalBatch, U = types.HistoricalBatch
	// kind = "HistoricalBatch"
	return generateSeedCorpus[*types.HistoricalBatch, types.HistoricalBatch]("HistoricalBatch", outZip)
}

func GenerateSeedCorpusHistoricalSummary(outZip string) error {
	// T = *types.HistoricalSummary, U = types.HistoricalSummary
	// kind = "HistoricalSummary"
	return generateSeedCorpus[*types.HistoricalSummary, types.HistoricalSummary]("HistoricalSummary", outZip)
}

func GenerateSeedCorpusIndexedAttestation(outZip string) error {
	// T = *types.IndexedAttestation, U = types.IndexedAttestation
	// kind = "IndexedAttestation"
	return generateSeedCorpus[*types.IndexedAttestation, types.IndexedAttestation]("IndexedAttestation", outZip)
}

func GenerateSeedCorpusAttesterSlashing(outZip string) error {
	// T = *types.AttesterSlashing, U = types.AttesterSlashing
	// kind = "AttesterSlashing"
	return generateSeedCorpus[*types.AttesterSlashing, types.AttesterSlashing]("AttesterSlashing", outZip)
}

func GenerateSeedCorpusPendingAttestation(outZip string) error {
	// T = *types.PendingAttestation, U = types.PendingAttestation
	// kind = "PendingAttestation"
	return generateSeedCorpus[*types.PendingAttestation, types.PendingAttestation]("PendingAttestation", outZip)
}

func GenerateSeedCorpusSignedBeaconBlockHeader(outZip string) error {
	// T = *types.SignedBeaconBlockHeader, U = types.SignedBeaconBlockHeader
	// kind = "SignedBeaconBlockHeader"
	return generateSeedCorpus[*types.SignedBeaconBlockHeader, types.SignedBeaconBlockHeader]("SignedBeaconBlockHeader", outZip)
}

func GenerateSeedCorpusProposerSlashing(outZip string) error {
	// T = *types.ProposerSlashing, U = types.ProposerSlashing
	// kind = "ProposerSlashing"
	return generateSeedCorpus[*types.ProposerSlashing, types.ProposerSlashing]("ProposerSlashing", outZip)
}

func GenerateSeedCorpusSignedBLSToExecutionChange(outZip string) error {
	// T = *types.SignedBLSToExecutionChange, U = types.SignedBLSToExecutionChange
	// kind = "SignedBLSToExecutionChange"
	return generateSeedCorpus[*types.SignedBLSToExecutionChange, types.SignedBLSToExecutionChange]("SignedBLSToExecutionChange", outZip)
}

func GenerateSeedCorpusSyncAggregate(outZip string) error {
	// T = *types.SyncAggregate, U = types.SyncAggregate
	// kind = "SyncAggregate"
	return generateSeedCorpus[*types.SyncAggregate, types.SyncAggregate]("SyncAggregate", outZip)
}

func GenerateSeedCorpusSyncCommittee(outZip string) error {
	// T = *types.SyncCommittee, U = types.SyncCommittee
	// kind = "SyncCommittee"
	return generateSeedCorpus[*types.SyncCommittee, types.SyncCommittee]("SyncCommittee", outZip)
}

func GenerateSeedCorpusVoluntaryExit(outZip string) error {
	// T = *types.VoluntaryExit, U = types.VoluntaryExit
	// kind = "VoluntaryExit"
	return generateSeedCorpus[*types.VoluntaryExit, types.VoluntaryExit]("VoluntaryExit", outZip)
}

func GenerateSeedCorpusSignedVoluntaryExit(outZip string) error {
	// T = *types.SignedVoluntaryExit, U = types.SignedVoluntaryExit
	// kind = "SignedVoluntaryExit"
	return generateSeedCorpus[*types.SignedVoluntaryExit, types.SignedVoluntaryExit]("SignedVoluntaryExit", outZip)
}

func GenerateSeedCorpusValidator(outZip string) error {
	// T = *types.Validator, U = types.Validator
	// kind = "Validator"
	return generateSeedCorpus[*types.Validator, types.Validator]("Validator", outZip)
}

func GenerateSeedCorpusWithdrawal(outZip string) error {
	// T = *types.Withdrawal, U = types.Withdrawal
	// kind = "Withdrawal"
	return generateSeedCorpus[*types.Withdrawal, types.Withdrawal]("Withdrawal", outZip)
}

func GenerateSeedCorpusExecutionPayloadCapella(outZip string) error {
	// T = *types.ExecutionPayloadCapella, U = types.ExecutionPayloadCapella
	// kind = "ExecutionPayloadCapella"
	return generateSeedCorpus[*types.ExecutionPayloadCapella, types.ExecutionPayloadCapella]("ExecutionPayloadCapella", outZip)
}

func GenerateSeedCorpusExecutionPayloadHeaderCapella(outZip string) error {
	// T = *types.ExecutionPayloadHeaderCapella, U = types.ExecutionPayloadHeaderCapella
	// kind = "ExecutionPayloadHeaderCapella"
	return generateSeedCorpus[*types.ExecutionPayloadHeaderCapella, types.ExecutionPayloadHeaderCapella]("ExecutionPayloadHeaderCapella", outZip)
}

func GenerateSeedCorpusExecutionPayloadDeneb(outZip string) error {
	// T = *types.ExecutionPayloadDeneb, U = types.ExecutionPayloadDeneb
	// kind = "ExecutionPayloadDeneb"
	return generateSeedCorpus[*types.ExecutionPayloadDeneb, types.ExecutionPayloadDeneb]("ExecutionPayloadDeneb", outZip)
}

func GenerateSeedCorpusExecutionPayloadHeaderDeneb(outZip string) error {
	// T = *types.ExecutionPayloadHeaderDeneb, U = types.ExecutionPayloadHeaderDeneb
	// kind = "ExecutionPayloadHeaderDeneb"
	return generateSeedCorpus[*types.ExecutionPayloadHeaderDeneb, types.ExecutionPayloadHeaderDeneb]("ExecutionPayloadHeaderDeneb", outZip)
}

func GenerateSeedCorpusBeaconState(outZip string) error {
	// T = *types.BeaconState, U = types.BeaconState
	// kind = "BeaconState"
	return generateSeedCorpus[*types.BeaconState, types.BeaconState]("BeaconState", outZip)
}

func GenerateSeedCorpusBeaconStateAltair(outZip string) error {
	// T = *types.BeaconStateAltair, U = types.BeaconStateAltair
	// kind = "BeaconStateAltair"
	return generateSeedCorpus[*types.BeaconStateAltair, types.BeaconStateAltair]("BeaconStateAltair", outZip)
}

func GenerateSeedCorpusBeaconStateBellatrix(outZip string) error {
	// T = *types.BeaconStateBellatrix, U = types.BeaconStateBellatrix
	// kind = "BeaconStateBellatrix"
	return generateSeedCorpus[*types.BeaconStateBellatrix, types.BeaconStateBellatrix]("BeaconStateBellatrix", outZip)
}

func GenerateSeedCorpusBeaconStateCapella(outZip string) error {
	// T = *types.BeaconStateCapella, U = types.BeaconStateCapella
	// kind = "BeaconStateCapella"
	return generateSeedCorpus[*types.BeaconStateCapella, types.BeaconStateCapella]("BeaconStateCapella", outZip)
}

func GenerateSeedCorpusBeaconStateDeneb(outZip string) error {
	// T = *types.BeaconStateDeneb, U = types.BeaconStateDeneb
	// kind = "BeaconStateDeneb"
	return generateSeedCorpus[*types.BeaconStateDeneb, types.BeaconStateDeneb]("BeaconStateDeneb", outZip)
}

func GenerateSeedCorpusBeaconBlockBody(outZip string) error {
	// T = *types.BeaconBlockBody, U = types.BeaconBlockBody
	// kind = "BeaconBlockBody"
	return generateSeedCorpus[*types.BeaconBlockBody, types.BeaconBlockBody]("BeaconBlockBody", outZip)
}

func GenerateSeedCorpusBeaconBlockBodyAltair(outZip string) error {
	// T = *types.BeaconBlockBodyAltair, U = types.BeaconBlockBodyAltair
	// kind = "BeaconBlockBodyAltair"
	return generateSeedCorpus[*types.BeaconBlockBodyAltair, types.BeaconBlockBodyAltair]("BeaconBlockBodyAltair", outZip)
}

func GenerateSeedCorpusBeaconBlockBodyBellatrix(outZip string) error {
	// T = *types.BeaconBlockBodyBellatrix, U = types.BeaconBlockBodyBellatrix
	// kind = "BeaconBlockBodyBellatrix"
	return generateSeedCorpus[*types.BeaconBlockBodyBellatrix, types.BeaconBlockBodyBellatrix]("BeaconBlockBodyBellatrix", outZip)
}

func GenerateSeedCorpusBeaconBlockBodyCapella(outZip string) error {
	// T = *types.BeaconBlockBodyCapella, U = types.BeaconBlockBodyCapella
	// kind = "BeaconBlockBodyCapella"
	return generateSeedCorpus[*types.BeaconBlockBodyCapella, types.BeaconBlockBodyCapella]("BeaconBlockBodyCapella", outZip)
}

func GenerateSeedCorpusBeaconBlockBodyDeneb(outZip string) error {
	// T = *types.BeaconBlockBodyDeneb, U = types.BeaconBlockBodyDeneb
	// kind = "BeaconBlockBodyDeneb"
	return generateSeedCorpus[*types.BeaconBlockBodyDeneb, types.BeaconBlockBodyDeneb]("BeaconBlockBodyDeneb", outZip)
}

func GenerateSeedCorpusBeaconBlock(outZip string) error {
	// T = *types.BeaconBlock, U = types.BeaconBlock
	// kind = "BeaconBlock"
	return generateSeedCorpus[*types.BeaconBlock, types.BeaconBlock]("BeaconBlock", outZip)
}

func GenerateSeedCorpusSingleFieldTestStructMonolith(outZip string) error {
	// T = *types.SingleFieldTestStructMonolith, U = types.SingleFieldTestStructMonolith
	// kind = "SingleFieldTestStructMonolith"
	return generateSeedCorpus[*types.SingleFieldTestStructMonolith, types.SingleFieldTestStructMonolith]("SingleFieldTestStructMonolith", outZip)
}

func GenerateSeedCorpusSmallTestStructMonolith(outZip string) error {
	// T = *types.SmallTestStructMonolith, U = types.SmallTestStructMonolith
	// kind = "SmallTestStructMonolith"
	return generateSeedCorpus[*types.SmallTestStructMonolith, types.SmallTestStructMonolith]("SmallTestStructMonolith", outZip)
}

func GenerateSeedCorpusFixedTestStructMonolith(outZip string) error {
	// T = *types.FixedTestStructMonolith, U = types.FixedTestStructMonolith
	// kind = "FixedTestStructMonolith"
	return generateSeedCorpus[*types.FixedTestStructMonolith, types.FixedTestStructMonolith]("FixedTestStructMonolith", outZip)
}

func GenerateSeedCorpusBitsStructMonolith(outZip string) error {
	// T = *types.BitsStructMonolith, U = types.BitsStructMonolith
	// kind = "BitsStructMonolith"
	return generateSeedCorpus[*types.BitsStructMonolith, types.BitsStructMonolith]("BitsStructMonolith", outZip)
}

func GenerateSeedCorpusExecutionPayloadMonolith(outZip string) error {
	// T = *types.ExecutionPayloadMonolith, U = types.ExecutionPayloadMonolith
	// kind = "ExecutionPayloadMonolith"
	return generateSeedCorpus[*types.ExecutionPayloadMonolith, types.ExecutionPayloadMonolith]("ExecutionPayloadMonolith", outZip)
}

func GenerateSeedCorpusExecutionPayloadMonolith2(outZip string) error {
	// T = *types.ExecutionPayloadMonolith2, U = types.ExecutionPayloadMonolith2
	// kind = "ExecutionPayloadMonolith2"
	return generateSeedCorpus[*types.ExecutionPayloadMonolith2, types.ExecutionPayloadMonolith2]("ExecutionPayloadMonolith2", outZip)
}

func GenerateSeedCorpusExecutionPayloadHeaderMonolith(outZip string) error {
	// T = *types.ExecutionPayloadHeaderMonolith, U = types.ExecutionPayloadHeaderMonolith
	// kind = "ExecutionPayloadHeaderMonolith"
	return generateSeedCorpus[*types.ExecutionPayloadHeaderMonolith, types.ExecutionPayloadHeaderMonolith]("ExecutionPayloadHeaderMonolith", outZip)
}

func GenerateSeedCorpusBeaconBlockBodyMonolith(outZip string) error {
	// T = *types.BeaconBlockBodyMonolith, U = types.BeaconBlockBodyMonolith
	// kind = "BeaconBlockBodyMonolith"
	return generateSeedCorpus[*types.BeaconBlockBodyMonolith, types.BeaconBlockBodyMonolith]("BeaconBlockBodyMonolith", outZip)
}

func GenerateSeedCorpusBeaconStateMonolith(outZip string) error {
	// T = *types.BeaconStateMonolith, U = types.BeaconStateMonolith
	// kind = "BeaconStateMonolith"
	return generateSeedCorpus[*types.BeaconStateMonolith, types.BeaconStateMonolith]("BeaconStateMonolith", outZip)
}

func GenerateSeedCorpusValidatorMonolith(outZip string) error {
	// T = *types.ValidatorMonolith, U = types.ValidatorMonolith
	// kind = "ValidatorMonolith"
	return generateSeedCorpus[*types.ValidatorMonolith, types.ValidatorMonolith]("ValidatorMonolith", outZip)
}

func GenerateSeedCorpusWithdrawalVariation(outZip string) error {
	// T = *types.WithdrawalVariation, U = types.WithdrawalVariation
	// kind = "WithdrawalVariation"
	return generateSeedCorpus[*types.WithdrawalVariation, types.WithdrawalVariation]("WithdrawalVariation", outZip)
}

func GenerateSeedCorpusHistoricalBatchVariation(outZip string) error {
	// T = *types.HistoricalBatchVariation, U = types.HistoricalBatchVariation
	// kind = "HistoricalBatchVariation"
	return generateSeedCorpus[*types.HistoricalBatchVariation, types.HistoricalBatchVariation]("HistoricalBatchVariation", outZip)
}

func GenerateSeedCorpusExecutionPayloadVariation(outZip string) error {
	// T = *types.ExecutionPayloadVariation, U = types.ExecutionPayloadVariation
	// kind = "ExecutionPayloadVariation"
	return generateSeedCorpus[*types.ExecutionPayloadVariation, types.ExecutionPayloadVariation]("ExecutionPayloadVariation", outZip)
}

func GenerateSeedCorpusAttestationVariation1(outZip string) error {
	// T = *types.AttestationVariation1, U = types.AttestationVariation1
	// kind = "AttestationVariation1"
	return generateSeedCorpus[*types.AttestationVariation1, types.AttestationVariation1]("AttestationVariation1", outZip)
}

func GenerateSeedCorpusAttestationVariation2(outZip string) error {
	// T = *types.AttestationVariation2, U = types.AttestationVariation2
	// kind = "AttestationVariation2"
	return generateSeedCorpus[*types.AttestationVariation2, types.AttestationVariation2]("AttestationVariation2", outZip)
}

func GenerateSeedCorpusAttestationVariation3(outZip string) error {
	// T = *types.AttestationVariation3, U = types.AttestationVariation3
	// kind = "AttestationVariation3"
	return generateSeedCorpus[*types.AttestationVariation3, types.AttestationVariation3]("AttestationVariation3", outZip)
}

func GenerateSeedCorpusAttestationDataVariation1(outZip string) error {
	// T = *types.AttestationDataVariation1, U = types.AttestationDataVariation1
	// kind = "AttestationDataVariation1"
	return generateSeedCorpus[*types.AttestationDataVariation1, types.AttestationDataVariation1]("AttestationDataVariation1", outZip)
}

func GenerateSeedCorpusAttestationDataVariation2(outZip string) error {
	// T = *types.AttestationDataVariation2, U = types.AttestationDataVariation2
	// kind = "AttestationDataVariation2"
	return generateSeedCorpus[*types.AttestationDataVariation2, types.AttestationDataVariation2]("AttestationDataVariation2", outZip)
}

func GenerateSeedCorpusAttestationDataVariation3(outZip string) error {
	// T = *types.AttestationDataVariation3, U = types.AttestationDataVariation3
	// kind = "AttestationDataVariation3"
	return generateSeedCorpus[*types.AttestationDataVariation3, types.AttestationDataVariation3]("AttestationDataVariation3", outZip)
}
