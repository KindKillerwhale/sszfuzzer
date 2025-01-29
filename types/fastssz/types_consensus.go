// ssz: Go Simple Serialize (SSZ) codec library
// Copyright 2024 ssz Authors
// SPDX-License-Identifier: BSD-3-Clause

package fastssz

import (
	"github.com/prysmaticlabs/go-bitfield"
)

//go:generate go run github.com/ferranbt/fastssz/sszgen -path=types_consensus.go -objs=SingleFieldTestStruct,SmallTestStruct,FixedTestStruct,BitsStruct,Checkpoint,AttestationData,BeaconBlockHeader,BLSToExecutionChange,Attestation,AggregateAndProof,DepositData,DepositMessage,Deposit,Eth1Block,Eth1Data,ExecutionPayload,ExecutionPayloadHeader,Fork,HistoricalBatch,HistoricalSummary,IndexedAttestation,AttesterSlashing,PendingAttestation,SignedBeaconBlockHeader,ProposerSlashing,SignedBLSToExecutionChange,SyncAggregate,SyncCommittee,VoluntaryExit,SignedVoluntaryExit,Validator,Withdrawal,ExecutionPayloadCapella,ExecutionPayloadHeaderCapella,ExecutionPayloadDeneb,ExecutionPayloadHeaderDeneb,BeaconState,BeaconStateAltair,BeaconStateBellatrix,BeaconStateCapella,BeaconStateDeneb,BeaconBlockBody,BeaconBlockBodyAltair,BeaconBlockBodyBellatrix,BeaconBlockBodyCapella,BeaconBlockBodyDeneb,BeaconBlock,SingleFieldTestStructMonolith,SmallTestStructMonolith,FixedTestStructMonolith,BitsStructMonolith,ExecutionPayloadMonolith,ExecutionPayloadMonolith2,ExecutionPayloadHeaderMonolith,BeaconBlockBodyMonolith,BeaconStateMonolith,ValidatorMonolith,WithdrawalVariation,HistoricalBatchVariation,ExecutionPayloadVariation,AttestationVariation1,AttestationVariation2,AttestationVariation3,AttestationDataVariation1,AttestationDataVariation2,AttestationDataVariation3 -output=gen_consensus_fastssz.go

// Slot is an alias of uint64
type Slot uint64

// Hash is a standalone mock of go-ethereum;s common.Hash
type Hash [32]byte

// Address is a standalone mock of go-ethereum's common.Address
type Address [20]byte

// LogsBloom is a standalone mock of go-ethereum's types.LogsBloom
type LogsBloom [256]byte

type AggregateAndProof struct {
	Index          uint64
	Aggregate      *Attestation
	SelectionProof [96]byte
}

type Attestation struct {
	AggregationBits bitfield.Bitlist `ssz-max:"2048"`
	Data            *AttestationData
	Signature       [96]byte
}

type AttestationData struct {
	Slot            Slot
	Index           uint64
	BeaconBlockHash Hash
	Source          *Checkpoint
	Target          *Checkpoint
}

type AttesterSlashing struct {
	Attestation1 *IndexedAttestation
	Attestation2 *IndexedAttestation
}

type BeaconBlock struct {
	Slot          Slot
	ProposerIndex uint64
	ParentRoot    Hash
	StateRoot     Hash
	Body          *BeaconBlockBody
}

type BeaconBlockHeader struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    Hash
	StateRoot     Hash
	BodyRoot      Hash
}

type BeaconBlockBody struct {
	RandaoReveal      [96]byte
	Eth1Data          *Eth1Data
	Graffiti          [32]byte
	ProposerSlashings []*ProposerSlashing    `ssz-max:"16"`
	AttesterSlashings []*AttesterSlashing    `ssz-max:"2"`
	Attestations      []*Attestation         `ssz-max:"128"`
	Deposits          []*Deposit             `ssz-max:"16"`
	VoluntaryExits    []*SignedVoluntaryExit `ssz-max:"16"`
}

type BeaconBlockBodyAltair struct {
	RandaoReveal      [96]byte
	Eth1Data          *Eth1Data
	Graffiti          [32]byte
	ProposerSlashings []*ProposerSlashing    `ssz-max:"16"`
	AttesterSlashings []*AttesterSlashing    `ssz-max:"2"`
	Attestations      []*Attestation         `ssz-max:"128"`
	Deposits          []*Deposit             `ssz-max:"16"`
	VoluntaryExits    []*SignedVoluntaryExit `ssz-max:"16"`
	SyncAggregate     *SyncAggregate
}

type BeaconBlockBodyBellatrix struct {
	RandaoReveal      [96]byte
	Eth1Data          *Eth1Data
	Graffiti          [32]byte
	ProposerSlashings []*ProposerSlashing    `ssz-max:"16"`
	AttesterSlashings []*AttesterSlashing    `ssz-max:"2"`
	Attestations      []*Attestation         `ssz-max:"128"`
	Deposits          []*Deposit             `ssz-max:"16"`
	VoluntaryExits    []*SignedVoluntaryExit `ssz-max:"16"`
	SyncAggregate     *SyncAggregate
	ExecutionPayload  *ExecutionPayload
}

type BeaconBlockBodyCapella struct {
	RandaoReveal          [96]byte
	Eth1Data              *Eth1Data
	Graffiti              [32]byte
	ProposerSlashings     []*ProposerSlashing    `ssz-max:"16"`
	AttesterSlashings     []*AttesterSlashing    `ssz-max:"2"`
	Attestations          []*Attestation         `ssz-max:"128"`
	Deposits              []*Deposit             `ssz-max:"16"`
	VoluntaryExits        []*SignedVoluntaryExit `ssz-max:"16"`
	SyncAggregate         *SyncAggregate
	ExecutionPayload      *ExecutionPayloadCapella
	BlsToExecutionChanges []*SignedBLSToExecutionChange `ssz-max:"16"`
}

type BeaconBlockBodyDeneb struct {
	RandaoReveal          [96]byte
	Eth1Data              *Eth1Data
	Graffiti              [32]byte
	ProposerSlashings     []*ProposerSlashing    `ssz-max:"16"`
	AttesterSlashings     []*AttesterSlashing    `ssz-max:"2"`
	Attestations          []*Attestation         `ssz-max:"128"`
	Deposits              []*Deposit             `ssz-max:"16"`
	VoluntaryExits        []*SignedVoluntaryExit `ssz-max:"16"`
	SyncAggregate         *SyncAggregate
	ExecutionPayload      *ExecutionPayloadDeneb
	BlsToExecutionChanges []*SignedBLSToExecutionChange `ssz-max:"16"`
	BlobKzgCommitments    [][48]byte                    `ssz-max:"4096"`
}

type BeaconState struct {
	GenesisTime           uint64
	GenesisValidatorsRoot [32]byte
	Slot                  uint64
	Fork                  *Fork
	LatestBlockHeader     *BeaconBlockHeader
	// BlockRoots                  [8192][32]byte
	// StateRoots                  [8192][32]byte
	BlockRoots       [][32]byte `ssz-max:"8192"`
	StateRoots       [][32]byte `ssz-max:"8192"`
	HistoricalRoots  [][32]byte `ssz-max:"16777216"`
	Eth1Data         *Eth1Data
	Eth1DataVotes    []*Eth1Data `ssz-max:"2048"`
	Eth1DepositIndex uint64
	Validators       []*Validator `ssz-max:"1099511627776"`
	Balances         []uint64     `ssz-max:"1099511627776"`
	// RandaoMixes                 [65536][32]byte
	RandaoMixes [][32]byte `ssz-max:"65536"`
	// Slashings                   [8192]uint64
	Slashings                   []uint64              `ssz-max:"8192"`
	PreviousEpochAttestations   []*PendingAttestation `ssz-max:"4096"`
	CurrentEpochAttestations    []*PendingAttestation `ssz-max:"4096"`
	JustificationBits           [1]byte               `ssz-size:"4" ssz:"bits"`
	PreviousJustifiedCheckpoint *Checkpoint
	CurrentJustifiedCheckpoint  *Checkpoint
	FinalizedCheckpoint         *Checkpoint
}

type BeaconStateAltair struct {
	GenesisTime           uint64
	GenesisValidatorsRoot []byte `ssz-size:"32"`
	Slot                  uint64
	Fork                  *Fork
	LatestBlockHeader     *BeaconBlockHeader
	// BlockRoots                  [8192][32]byte
	// StateRoots                  [8192][32]byte
	BlockRoots       [][32]byte `ssz-max:"8192"`
	StateRoots       [][32]byte `ssz-max:"8192"`
	HistoricalRoots  [][32]byte `ssz-max:"16777216"`
	Eth1Data         *Eth1Data
	Eth1DataVotes    []*Eth1Data `ssz-max:"2048"`
	Eth1DepositIndex uint64
	Validators       []*Validator `ssz-max:"1099511627776"`
	Balances         []uint64     `ssz-max:"1099511627776"`
	// RandaoMixes                 [65536][32]byte
	RandaoMixes [][32]byte `ssz-max:"65536"`
	// Slashings                   [8192]uint64
	Slashings                   []uint64 `ssz-max:"8192"`
	PreviousEpochParticipation  []byte   `ssz-max:"1099511627776"`
	CurrentEpochParticipation   []byte   `ssz-max:"1099511627776"`
	JustificationBits           [1]byte  `ssz-size:"4" ssz:"bits"`
	PreviousJustifiedCheckpoint *Checkpoint
	CurrentJustifiedCheckpoint  *Checkpoint
	FinalizedCheckpoint         *Checkpoint
	InactivityScores            []uint64 `ssz-max:"1099511627776"`
	CurrentSyncCommittee        *SyncCommittee
	NextSyncCommittee           *SyncCommittee
}

type BeaconStateBellatrix struct {
	GenesisTime           uint64
	GenesisValidatorsRoot [32]byte
	Slot                  uint64
	Fork                  *Fork
	LatestBlockHeader     *BeaconBlockHeader
	// BlockRoots                  [8192][32]byte
	// StateRoots                  [8192][32]byte
	BlockRoots       [][32]byte `ssz-max:"8192"`
	StateRoots       [][32]byte `ssz-max:"8192"`
	HistoricalRoots  [][32]byte `ssz-max:"16777216"`
	Eth1Data         *Eth1Data
	Eth1DataVotes    []*Eth1Data `ssz-max:"2048"`
	Eth1DepositIndex uint64
	Validators       []*Validator `ssz-max:"1099511627776"`
	Balances         []uint64     `ssz-max:"1099511627776"`
	// RandaoMixes                  [65536][32]byte
	RandaoMixes [][32]byte `ssz-max:"65536"`
	// Slashings                    [8192]uint64
	Slashings                    []uint64 `ssz-max:"8192"`
	PreviousEpochParticipation   []byte   `ssz-max:"1099511627776"`
	CurrentEpochParticipation    []byte   `ssz-max:"1099511627776"`
	JustificationBits            [1]byte  `ssz-size:"4" ssz:"bits"`
	PreviousJustifiedCheckpoint  *Checkpoint
	CurrentJustifiedCheckpoint   *Checkpoint
	FinalizedCheckpoint          *Checkpoint
	InactivityScores             []uint64 `ssz-max:"1099511627776"`
	CurrentSyncCommittee         *SyncCommittee
	NextSyncCommittee            *SyncCommittee
	LatestExecutionPayloadHeader *ExecutionPayloadHeader
}

type BeaconStateCapella struct {
	GenesisTime           uint64
	GenesisValidatorsRoot [32]byte
	Slot                  uint64
	Fork                  *Fork
	LatestBlockHeader     *BeaconBlockHeader
	// BlockRoots                  [8192][32]byte
	// StateRoots                  [8192][32]byte
	BlockRoots       [][32]byte `ssz-max:"8192"`
	StateRoots       [][32]byte `ssz-max:"8192"`
	HistoricalRoots  [][32]byte `ssz-max:"16777216"`
	Eth1Data         *Eth1Data
	Eth1DataVotes    []*Eth1Data `ssz-max:"2048"`
	Eth1DepositIndex uint64
	Validators       []*Validator `ssz-max:"1099511627776"`
	Balances         []uint64     `ssz-max:"1099511627776"`
	// RandaoMixes                  [65536][32]byte
	RandaoMixes [][32]byte `ssz-max:"65536"`
	// Slashings                    [8192]uint64
	Slashings                    []uint64 `ssz-max:"8192"`
	PreviousEpochParticipation   []byte   `ssz-max:"1099511627776"`
	CurrentEpochParticipation    []byte   `ssz-max:"1099511627776"`
	JustificationBits            [1]byte  `ssz-size:"4" ssz:"bits"`
	PreviousJustifiedCheckpoint  *Checkpoint
	CurrentJustifiedCheckpoint   *Checkpoint
	FinalizedCheckpoint          *Checkpoint
	InactivityScores             []uint64 `ssz-max:"1099511627776"`
	CurrentSyncCommittee         *SyncCommittee
	NextSyncCommittee            *SyncCommittee
	LatestExecutionPayloadHeader *ExecutionPayloadHeaderCapella
	NextWithdrawalIndex          uint64
	NextWithdrawalValidatorIndex uint64
	HistoricalSummaries          []*HistoricalSummary `ssz-max:"16777216"`
}

type BeaconStateDeneb struct {
	GenesisTime           uint64
	GenesisValidatorsRoot [32]byte
	Slot                  uint64
	Fork                  *Fork
	LatestBlockHeader     *BeaconBlockHeader
	// BlockRoots                  [8192][32]byte
	// StateRoots                  [8192][32]byte
	BlockRoots       [][32]byte `ssz-max:"8192"`
	StateRoots       [][32]byte `ssz-max:"8192"`
	HistoricalRoots  [][32]byte `ssz-max:"16777216"`
	Eth1Data         *Eth1Data
	Eth1DataVotes    []*Eth1Data `ssz-max:"2048"`
	Eth1DepositIndex uint64
	Validators       []*Validator `ssz-max:"1099511627776"`
	Balances         []uint64     `ssz-max:"1099511627776"`
	// RandaoMixes                  [65536][32]byte
	RandaoMixes [][32]byte `ssz-max:"65536"`
	// Slashings                    [8192]uint64
	Slashings                    []uint64 `ssz-max:"8192"`
	PreviousEpochParticipation   []byte   `ssz-max:"1099511627776"`
	CurrentEpochParticipation    []byte   `ssz-max:"1099511627776"`
	JustificationBits            [1]byte  `ssz-size:"4" ssz:"bits"`
	PreviousJustifiedCheckpoint  *Checkpoint
	CurrentJustifiedCheckpoint   *Checkpoint
	FinalizedCheckpoint          *Checkpoint
	InactivityScores             []uint64 `ssz-max:"1099511627776"`
	CurrentSyncCommittee         *SyncCommittee
	NextSyncCommittee            *SyncCommittee
	LatestExecutionPayloadHeader *ExecutionPayloadHeaderDeneb
	NextWithdrawalIndex          uint64
	NextWithdrawalValidatorIndex uint64
	HistoricalSummaries          []*HistoricalSummary `ssz-max:"16777216"`
}

type BLSToExecutionChange struct {
	ValidatorIndex     uint64
	FromBLSPubKey      [48]byte
	ToExecutionAddress [20]byte
}

type Checkpoint struct {
	Epoch uint64
	Root  Hash
}

type Deposit struct {
	// Proof [33][32]byte
	Proof [][32]byte `ssz-max:"33"`
	Data  *DepositData
}

type DepositData struct {
	Pubkey                [48]byte
	WithdrawalCredentials [32]byte
	Amount                uint64
	Signature             [96]byte
}

type DepositMessage struct {
	Pubkey                [48]byte
	WithdrawalCredentials [32]byte
	Amount                uint64
}

type Eth1Block struct {
	Timestamp    uint64
	DepositRoot  [32]byte
	DepositCount uint64
}
type Eth1Data struct {
	DepositRoot  Hash
	DepositCount uint64
	BlockHash    Hash
}

type ExecutionPayload struct {
	ParentHash   Hash
	FeeRecipient Address
	StateRoot    Hash
	ReceiptsRoot Hash
	LogsBloom    LogsBloom
	PrevRandao   Hash
	BlockNumber  uint64
	GasLimit     uint64
	GasUsed      uint64
	Timestamp    uint64
	ExtraData    []byte `ssz-max:"32"`
	// BaseFeePerGas *uint256.Int
	BaseFeePerGas [32]byte
	BlockHash     Hash
	Transactions  [][]byte `ssz-max:"1048576,1073741824"`
}

type ExecutionPayloadCapella struct {
	ParentHash   Hash
	FeeRecipient Address
	StateRoot    Hash
	ReceiptsRoot Hash
	LogsBloom    LogsBloom
	PrevRandao   Hash
	BlockNumber  uint64
	GasLimit     uint64
	GasUsed      uint64
	Timestamp    uint64
	ExtraData    []byte `ssz-max:"32"`
	// BaseFeePerGas *uint256.Int
	BaseFeePerGas [32]byte
	BlockHash     Hash
	Transactions  [][]byte      `ssz-max:"1048576,1073741824"`
	Withdrawals   []*Withdrawal `ssz-max:"16"`
}

type ExecutionPayloadDeneb struct {
	ParentHash   Hash
	FeeRecipient Address
	StateRoot    Hash
	ReceiptsRoot Hash
	LogsBloom    LogsBloom
	PrevRandao   Hash
	BlockNumber  uint64
	GasLimit     uint64
	GasUsed      uint64
	Timestamp    uint64
	ExtraData    []byte `ssz-max:"32"`
	// BaseFeePerGas *uint256.Int
	BaseFeePerGas [32]byte
	BlockHash     Hash
	Transactions  [][]byte      `ssz-max:"1048576,1073741824"`
	Withdrawals   []*Withdrawal `ssz-max:"16"`
	BlobGasUsed   uint64
	ExcessBlobGas uint64
}

type ExecutionPayloadHeader struct {
	ParentHash       [32]byte
	FeeRecipient     [20]byte
	StateRoot        [32]byte
	ReceiptsRoot     [32]byte
	LogsBloom        [256]byte
	PrevRandao       [32]byte
	BlockNumber      uint64
	GasLimit         uint64
	GasUsed          uint64
	Timestamp        uint64
	ExtraData        []byte `ssz-max:"32"`
	BaseFeePerGas    [32]byte
	BlockHash        [32]byte
	TransactionsRoot [32]byte
}

type ExecutionPayloadHeaderCapella struct {
	ParentHash       [32]byte
	FeeRecipient     [20]byte
	StateRoot        [32]byte
	ReceiptsRoot     [32]byte
	LogsBloom        [256]byte
	PrevRandao       [32]byte
	BlockNumber      uint64
	GasLimit         uint64
	GasUsed          uint64
	Timestamp        uint64
	ExtraData        []byte `ssz-max:"32"`
	BaseFeePerGas    [32]byte
	BlockHash        [32]byte
	TransactionsRoot [32]byte
	WithdrawalRoot   [32]byte
}

type ExecutionPayloadHeaderDeneb struct {
	ParentHash       [32]byte
	FeeRecipient     [20]byte
	StateRoot        [32]byte
	ReceiptsRoot     [32]byte
	LogsBloom        [256]byte
	PrevRandao       [32]byte
	BlockNumber      uint64
	GasLimit         uint64
	GasUsed          uint64
	Timestamp        uint64
	ExtraData        []byte `ssz-max:"32"`
	BaseFeePerGas    [32]byte
	BlockHash        [32]byte
	TransactionsRoot [32]byte
	WithdrawalRoot   [32]byte
	BlobGasUsed      uint64
	ExcessBlobGas    uint64
}

type Fork struct {
	PreviousVersion [4]byte
	CurrentVersion  [4]byte
	Epoch           uint64
}

type HistoricalBatch struct {
	// BlockRoots [8192]Hash
	// Roots is a helper type to force a generator quirk.
	// type Roots [8192]Hash
	BlockRoots []Hash `ssz-max:"8192"`
	StateRoots []Hash `ssz-max:"8192"`
}

type HistoricalSummary struct {
	BlockSummaryRoot [32]byte
	StateSummaryRoot [32]byte
}

type IndexedAttestation struct {
	AttestationIndices []uint64 `ssz-max:"2048"`
	Data               *AttestationData
	Signature          [96]byte
}

type PendingAttestation struct {
	AggregationBits bitfield.Bitlist `ssz-max:"2048"`
	Data            *AttestationData
	InclusionDelay  uint64
	ProposerIndex   uint64
}

type ProposerSlashing struct {
	Header1 *SignedBeaconBlockHeader
	Header2 *SignedBeaconBlockHeader
}

type SignedBeaconBlockHeader struct {
	Header    *BeaconBlockHeader
	Signature [96]byte
}

type SignedBLSToExecutionChange struct {
	Message   *BLSToExecutionChange
	Signature [96]byte
}

type SignedVoluntaryExit struct {
	Exit      *VoluntaryExit
	Signature [96]byte
}

type SyncAggregate struct {
	SyncCommiteeBits      [64]byte
	SyncCommiteeSignature [96]byte
}

type SyncCommittee struct {
	// PubKeys         [512][48]byte
	PubKeys         [][48]byte `ssz-max:"512"`
	AggregatePubKey [48]byte
}

type VoluntaryExit struct {
	Epoch          uint64
	ValidatorIndex uint64
}

type Validator struct {
	Pubkey                     [48]byte
	WithdrawalCredentials      [32]byte
	EffectiveBalance           uint64
	Slashed                    bool
	ActivationEligibilityEpoch uint64
	ActivationEpoch            uint64
	ExitEpoch                  uint64
	WithdrawableEpoch          uint64
}

type Withdrawal struct {
	Index     uint64
	Validator uint64
	Address   Address
	Amount    uint64
}

type SingleFieldTestStruct struct {
	// A byte
	A uint8
}

type SmallTestStruct struct {
	A uint16
	B uint16
}

type FixedTestStruct struct {
	A uint8
	B uint64
	C uint32
}

type BitsStruct struct {
	A bitfield.Bitlist `ssz-max:"5"`
	B [1]byte          `ssz-size:"2" ssz:"bits"`
	C [1]byte          `ssz-size:"1" ssz:"bits"`
	D bitfield.Bitlist `ssz-max:"6"`
	E [1]byte          `ssz-size:"8" ssz:"bits"`
}

type SingleFieldTestStructMonolith struct {
	// A *byte `ssz-fork:"unknown"`
	A uint8 `ssz-fork:"unknown"`
}

type SmallTestStructMonolith struct {
	// A *uint16 `ssz-fork:"unknown"`
	A uint16 `ssz-fork:"unknown"`
	B uint16
}

type FixedTestStructMonolith struct {
	// A *uint8  `ssz-fork:"unknown"`
	// B *uint64 `ssz-fork:"unknown"`
	// C *uint32 `ssz-fork:"unknown"`
	A uint8  `ssz-fork:"unknown"`
	B uint64 `ssz-fork:"unknown"`
	C uint32 `ssz-fork:"unknown"`
}

type BitsStructMonolith struct {
	A bitfield.Bitlist `ssz-max:"5" ssz-fork:"unknown"`
	// B *[1]byte         `ssz-size:"2" ssz:"bits" ssz-fork:"unknown"`
	B [1]byte          `ssz-size:"2" ssz:"bits" ssz-fork:"unknown"`
	C [1]byte          `ssz-size:"1" ssz:"bits"`
	D bitfield.Bitlist `ssz-max:"6"`
	E [1]byte          `ssz-size:"8" ssz:"bits"`
}

type BeaconBlockBodyMonolith struct {
	RandaoReveal          [96]byte
	Eth1Data              *Eth1Data
	Graffiti              [32]byte
	ProposerSlashings     []*ProposerSlashing           `ssz-max:"16"`
	AttesterSlashings     []*AttesterSlashing           `ssz-max:"2"`
	Attestations          []*Attestation                `ssz-max:"128"`
	Deposits              []*Deposit                    `ssz-max:"16"`
	VoluntaryExits        []*SignedVoluntaryExit        `ssz-max:"16"`
	SyncAggregate         *SyncAggregate                `               ssz-fork:"altair"`
	ExecutionPayload      *ExecutionPayloadMonolith     `               ssz-fork:"bellatrix"`
	BlsToExecutionChanges []*SignedBLSToExecutionChange `ssz-max:"16"   ssz-fork:"capella"`
	BlobKzgCommitments    [][48]byte                    `ssz-max:"4096" ssz-fork:"deneb"`
}

type BeaconStateMonolith struct {
	GenesisTime           uint64
	GenesisValidatorsRoot [32]byte
	Slot                  uint64
	Fork                  *Fork
	LatestBlockHeader     *BeaconBlockHeader
	// BlockRoots                   [8192][32]byte
	// StateRoots                   [8192][32]byte
	BlockRoots       [][32]byte `ssz-max:"8192"`
	StateRoots       [][32]byte `ssz-max:"8192"`
	HistoricalRoots  [][32]byte `ssz-max:"16777216"`
	Eth1Data         *Eth1Data
	Eth1DataVotes    []*Eth1Data `ssz-max:"2048"`
	Eth1DepositIndex uint64
	Validators       []*Validator `ssz-max:"1099511627776"`
	Balances         []uint64     `ssz-max:"1099511627776"`
	// RandaoMixes                  [65536][32]byte
	// 	Slashings                    *[8192]uint64         `ssz-fork:"unknown"`
	RandaoMixes                  [][32]byte            `ssz-max:"65536"`
	Slashings                    []uint64              `ssz-max:"8192" ssz-fork:"unknown"`
	PreviousEpochAttestations    []*PendingAttestation `ssz-max:"4096"          ssz-fork:"!altair"`
	CurrentEpochAttestations     []*PendingAttestation `ssz-max:"4096"          ssz-fork:"!altair"`
	PreviousEpochParticipation   []byte                `ssz-max:"1099511627776" ssz-fork:"altair"`
	CurrentEpochParticipation    []byte                `ssz-max:"1099511627776" ssz-fork:"altair"`
	JustificationBits            [1]byte               `ssz-size:"4" ssz:"bits"`
	PreviousJustifiedCheckpoint  *Checkpoint
	CurrentJustifiedCheckpoint   *Checkpoint
	FinalizedCheckpoint          *Checkpoint
	InactivityScores             []uint64                        `ssz-max:"1099511627776" ssz-fork:"altair"`
	CurrentSyncCommittee         *SyncCommittee                  `                        ssz-fork:"altair"`
	NextSyncCommittee            *SyncCommittee                  `                        ssz-fork:"altair"`
	LatestExecutionPayloadHeader *ExecutionPayloadHeaderMonolith `                        ssz-fork:"bellatrix"`
	NextWithdrawalIndex          uint64                          `                        ssz-fork:"capella"`
	NextWithdrawalValidatorIndex uint64                          `                        ssz-fork:"capella"`
	HistoricalSummaries          []*HistoricalSummary            `ssz-max:"16777216"      ssz-fork:"capella"`
}

type ExecutionPayloadMonolith struct {
	ParentHash   Hash
	FeeRecipient Address
	StateRoot    Hash
	ReceiptsRoot Hash
	LogsBloom    LogsBloom
	PrevRandao   Hash
	BlockNumber  uint64
	GasLimit     uint64
	GasUsed      uint64
	Timestamp    uint64
	ExtraData    []byte `ssz-max:"32" ssz-fork:"frontier"`
	// BaseFeePerGas *uint256.Int `ssz-fork:"unknown"`
	BaseFeePerGas [32]byte `ssz-fork:"unknown"`
	BlockHash     Hash
	Transactions  [][]byte      `ssz-max:"1048576,1073741824" ssz-fork:"unknown"`
	Withdrawals   []*Withdrawal `ssz-max:"16" ssz-fork:"shanghai"`
	BlobGasUsed   uint64        `             ssz-fork:"cancun"`
	ExcessBlobGas uint64        `             ssz-fork:"cancun"`
}

type ExecutionPayloadMonolith2 struct {
	ParentHash   Hash
	FeeRecipient Address
	StateRoot    Hash
	ReceiptsRoot Hash
	LogsBloom    LogsBloom
	PrevRandao   Hash
	BlockNumber  uint64
	GasLimit     uint64
	GasUsed      uint64
	Timestamp    uint64
	ExtraData    []byte `ssz-max:"32" ssz-fork:"frontier"`
	// BaseFeePerGas *big.Int `ssz-fork:"unknown"`
	BaseFeePerGas [32]byte `ssz-fork:"unknown"`
	BlockHash     Hash
	Transactions  [][]byte      `ssz-max:"1048576,1073741824"`
	Withdrawals   []*Withdrawal `ssz-max:"16" ssz-fork:"shanghai"`
	BlobGasUsed   uint64        `             ssz-fork:"cancun"`
	ExcessBlobGas uint64        `             ssz-fork:"cancun"`
}

type ExecutionPayloadHeaderMonolith struct {
	ParentHash       [32]byte
	FeeRecipient     [20]byte
	StateRoot        [32]byte
	ReceiptsRoot     [32]byte
	LogsBloom        [256]byte
	PrevRandao       [32]byte
	BlockNumber      uint64
	GasLimit         uint64
	GasUsed          uint64
	Timestamp        uint64
	ExtraData        []byte `ssz-max:"32" ssz-fork:"frontier"`
	BaseFeePerGas    [32]byte
	BlockHash        [32]byte
	TransactionsRoot [32]byte
	WithdrawalRoot   [32]byte `ssz-fork:"shanghai"`
	BlobGasUsed      uint64   `ssz-fork:"cancun"`
	ExcessBlobGas    uint64   `ssz-fork:"cancun"`
}

type ValidatorMonolith struct {
	Pubkey                     [48]byte
	WithdrawalCredentials      [32]byte
	EffectiveBalance           uint64
	Slashed                    bool `ssz-fork:"unknown"`
	ActivationEligibilityEpoch uint64
	ActivationEpoch            uint64
	ExitEpoch                  uint64
	WithdrawableEpoch          uint64
}

type WithdrawalVariation struct {
	Index     uint64
	Validator uint64
	Address   []byte `ssz-size:"20"` // Static bytes defined via ssz-size tag
	Amount    uint64
}

type HistoricalBatchVariation struct {
	// Roots is a helper type to force a generator quirk.
	// type Roots [8192]Hash
	BlockRoots []Hash `ssz-max:"8192"`
	StateRoots []Hash `ssz-max:"8192" ssz-size:"8192"` // Static array defined via ssz-size tag
}

type ExecutionPayloadVariation struct {
	ParentHash   Hash
	FeeRecipient Address
	StateRoot    Hash
	ReceiptsRoot Hash
	LogsBloom    LogsBloom
	PrevRandao   Hash
	BlockNumber  uint64
	GasLimit     uint64
	GasUsed      uint64
	Timestamp    uint64
	ExtraData    []byte `ssz-max:"32"`
	// BaseFeePerGas *big.Int // Big.Int instead of the recommended uint256.Int
	BaseFeePerGas [32]byte
	BlockHash     Hash
	Transactions  [][]byte `ssz-max:"1048576,1073741824"`
}

// The types below test that fork constraints generate correct code for runtime
// types (i.e. static objects embedded) for various positions.

type AttestationVariation1 struct {
	Future          uint64           `ssz-fork:"future"` // Currently unused field
	AggregationBits bitfield.Bitlist `ssz-max:"2048"`
	Data            *AttestationData
	Signature       [96]byte
}
type AttestationVariation2 struct {
	AggregationBits bitfield.Bitlist `ssz-max:"2048"`
	Data            *AttestationData
	Future          uint64 `ssz-fork:"future"` // Currently unused field
	Signature       [96]byte
}
type AttestationVariation3 struct {
	AggregationBits bitfield.Bitlist `ssz-max:"2048"`
	Data            *AttestationData
	Signature       [96]byte
	Future          uint64 `ssz-fork:"future"` // Currently unused field
}

type AttestationDataVariation1 struct {
	Future          uint64 `ssz-fork:"future"` // Currently unused field
	Slot            Slot
	Index           uint64
	BeaconBlockHash Hash
	Source          *Checkpoint
	Target          *Checkpoint
}
type AttestationDataVariation2 struct {
	Slot            Slot
	Index           uint64
	BeaconBlockHash Hash
	Future          uint64 `ssz-fork:"future"` // Currently unused field
	Source          *Checkpoint
	Target          *Checkpoint
}
type AttestationDataVariation3 struct {
	Slot            Slot
	Index           uint64
	BeaconBlockHash Hash
	Source          *Checkpoint
	Target          *Checkpoint
	Future          uint64 `ssz-fork:"future"` // Currently unused field
}
