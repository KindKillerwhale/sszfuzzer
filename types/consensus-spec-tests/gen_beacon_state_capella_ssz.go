// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

import "github.com/karalabe/ssz"

// Cached static size computed on package init.
var staticSizeCacheBeaconStateCapella = ssz.PrecomputeStaticSizeCache((*BeaconStateCapella)(nil))

// SizeSSZ returns either the static size of the object if fixed == true, or
// the total size otherwise.
func (obj *BeaconStateCapella) SizeSSZ(sizer *ssz.Sizer, fixed bool) (size uint32) {
	// Load static size if already precomputed, calculate otherwise
	if fork := int(sizer.Fork()); fork < len(staticSizeCacheBeaconStateCapella) {
		size = staticSizeCacheBeaconStateCapella[fork]
	} else {
		size = 8 + 32 + 8 + (*Fork)(nil).SizeSSZ(sizer) + (*BeaconBlockHeader)(nil).SizeSSZ(sizer) + 8192*32 + 8192*32 + 4 + (*Eth1Data)(nil).SizeSSZ(sizer) + 4 + 8 + 4 + 4 + 65536*32 + 8192*8 + 4 + 4 + 1 + (*Checkpoint)(nil).SizeSSZ(sizer) + (*Checkpoint)(nil).SizeSSZ(sizer) + (*Checkpoint)(nil).SizeSSZ(sizer) + 4 + (*SyncCommittee)(nil).SizeSSZ(sizer) + (*SyncCommittee)(nil).SizeSSZ(sizer) + 4 + 8 + 8 + 4
	}
	// Either return the static size or accumulate the dynamic too
	if fixed {
		return size
	}
	size += ssz.SizeSliceOfStaticBytes(sizer, obj.HistoricalRoots)
	size += ssz.SizeSliceOfStaticObjects(sizer, obj.Eth1DataVotes)
	size += ssz.SizeSliceOfStaticObjects(sizer, obj.Validators)
	size += ssz.SizeSliceOfUint64s(sizer, obj.Balances)
	size += ssz.SizeDynamicBytes(sizer, obj.PreviousEpochParticipation)
	size += ssz.SizeDynamicBytes(sizer, obj.CurrentEpochParticipation)
	size += ssz.SizeSliceOfUint64s(sizer, obj.InactivityScores)
	size += ssz.SizeDynamicObject(sizer, obj.LatestExecutionPayloadHeader)
	size += ssz.SizeSliceOfStaticObjects(sizer, obj.HistoricalSummaries)

	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *BeaconStateCapella) DefineSSZ(codec *ssz.Codec) {
	// Define the static data (fields and dynamic offsets)
	ssz.DefineUint64(codec, &obj.GenesisTime)                                           // Field  ( 0) -                  GenesisTime -       8 bytes
	ssz.DefineStaticBytes(codec, &obj.GenesisValidatorsRoot)                            // Field  ( 1) -        GenesisValidatorsRoot -      32 bytes
	ssz.DefineUint64(codec, &obj.Slot)                                                  // Field  ( 2) -                         Slot -       8 bytes
	ssz.DefineStaticObject(codec, &obj.Fork)                                            // Field  ( 3) -                         Fork -       ? bytes (Fork)
	ssz.DefineStaticObject(codec, &obj.LatestBlockHeader)                               // Field  ( 4) -            LatestBlockHeader -       ? bytes (BeaconBlockHeader)
	ssz.DefineUnsafeArrayOfStaticBytes(codec, obj.BlockRoots[:])                        // Field  ( 5) -                   BlockRoots -  262144 bytes
	ssz.DefineUnsafeArrayOfStaticBytes(codec, obj.StateRoots[:])                        // Field  ( 6) -                   StateRoots -  262144 bytes
	ssz.DefineSliceOfStaticBytesOffset(codec, &obj.HistoricalRoots, 16777216)           // Offset ( 7) -              HistoricalRoots -       4 bytes
	ssz.DefineStaticObject(codec, &obj.Eth1Data)                                        // Field  ( 8) -                     Eth1Data -       ? bytes (Eth1Data)
	ssz.DefineSliceOfStaticObjectsOffset(codec, &obj.Eth1DataVotes, 2048)               // Offset ( 9) -                Eth1DataVotes -       4 bytes
	ssz.DefineUint64(codec, &obj.Eth1DepositIndex)                                      // Field  (10) -             Eth1DepositIndex -       8 bytes
	ssz.DefineSliceOfStaticObjectsOffset(codec, &obj.Validators, 1099511627776)         // Offset (11) -                   Validators -       4 bytes
	ssz.DefineSliceOfUint64sOffset(codec, &obj.Balances, 1099511627776)                 // Offset (12) -                     Balances -       4 bytes
	ssz.DefineUnsafeArrayOfStaticBytes(codec, obj.RandaoMixes[:])                       // Field  (13) -                  RandaoMixes - 2097152 bytes
	ssz.DefineArrayOfUint64s(codec, &obj.Slashings)                                     // Field  (14) -                    Slashings -   65536 bytes
	ssz.DefineDynamicBytesOffset(codec, &obj.PreviousEpochParticipation, 1099511627776) // Offset (15) -   PreviousEpochParticipation -       4 bytes
	ssz.DefineDynamicBytesOffset(codec, &obj.CurrentEpochParticipation, 1099511627776)  // Offset (16) -    CurrentEpochParticipation -       4 bytes
	ssz.DefineArrayOfBits(codec, &obj.JustificationBits, 4)                             // Field  (17) -            JustificationBits -       1 bytes
	ssz.DefineStaticObject(codec, &obj.PreviousJustifiedCheckpoint)                     // Field  (18) -  PreviousJustifiedCheckpoint -       ? bytes (Checkpoint)
	ssz.DefineStaticObject(codec, &obj.CurrentJustifiedCheckpoint)                      // Field  (19) -   CurrentJustifiedCheckpoint -       ? bytes (Checkpoint)
	ssz.DefineStaticObject(codec, &obj.FinalizedCheckpoint)                             // Field  (20) -          FinalizedCheckpoint -       ? bytes (Checkpoint)
	ssz.DefineSliceOfUint64sOffset(codec, &obj.InactivityScores, 1099511627776)         // Offset (21) -             InactivityScores -       4 bytes
	ssz.DefineStaticObject(codec, &obj.CurrentSyncCommittee)                            // Field  (22) -         CurrentSyncCommittee -       ? bytes (SyncCommittee)
	ssz.DefineStaticObject(codec, &obj.NextSyncCommittee)                               // Field  (23) -            NextSyncCommittee -       ? bytes (SyncCommittee)
	ssz.DefineDynamicObjectOffset(codec, &obj.LatestExecutionPayloadHeader)             // Offset (24) - LatestExecutionPayloadHeader -       4 bytes
	ssz.DefineUint64(codec, &obj.NextWithdrawalIndex)                                   // Field  (25) -          NextWithdrawalIndex -       8 bytes
	ssz.DefineUint64(codec, &obj.NextWithdrawalValidatorIndex)                          // Field  (26) - NextWithdrawalValidatorIndex -       8 bytes
	ssz.DefineSliceOfStaticObjectsOffset(codec, &obj.HistoricalSummaries, 16777216)     // Offset (27) -          HistoricalSummaries -       4 bytes

	// Define the dynamic data (fields)
	ssz.DefineSliceOfStaticBytesContent(codec, &obj.HistoricalRoots, 16777216)           // Field  ( 7) -              HistoricalRoots - ? bytes
	ssz.DefineSliceOfStaticObjectsContent(codec, &obj.Eth1DataVotes, 2048)               // Field  ( 9) -                Eth1DataVotes - ? bytes
	ssz.DefineSliceOfStaticObjectsContent(codec, &obj.Validators, 1099511627776)         // Field  (11) -                   Validators - ? bytes
	ssz.DefineSliceOfUint64sContent(codec, &obj.Balances, 1099511627776)                 // Field  (12) -                     Balances - ? bytes
	ssz.DefineDynamicBytesContent(codec, &obj.PreviousEpochParticipation, 1099511627776) // Field  (15) -   PreviousEpochParticipation - ? bytes
	ssz.DefineDynamicBytesContent(codec, &obj.CurrentEpochParticipation, 1099511627776)  // Field  (16) -    CurrentEpochParticipation - ? bytes
	ssz.DefineSliceOfUint64sContent(codec, &obj.InactivityScores, 1099511627776)         // Field  (21) -             InactivityScores - ? bytes
	ssz.DefineDynamicObjectContent(codec, &obj.LatestExecutionPayloadHeader)             // Field  (24) - LatestExecutionPayloadHeader - ? bytes
	ssz.DefineSliceOfStaticObjectsContent(codec, &obj.HistoricalSummaries, 16777216)     // Field  (27) -          HistoricalSummaries - ? bytes
}
