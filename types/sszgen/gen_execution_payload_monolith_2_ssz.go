// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// SizeSSZ returns either the static size of the object if fixed == true, or
// the total size otherwise.
func (obj *ExecutionPayloadMonolith2) SizeSSZ(sizer *ssz.Sizer, fixed bool) (size uint32) {
	size = 32 + 20 + 32 + 32 + 256 + 32 + 8 + 8 + 8 + 8
	if sizer.Fork() >= ssz.ForkFrontier {
		size += 4
	}
	if sizer.Fork() >= ssz.ForkUnknown {
		size += 32
	}
	size += 32 + 4
	if sizer.Fork() >= ssz.ForkShanghai {
		size += 4
	}
	if sizer.Fork() >= ssz.ForkCancun {
		size += 8 + 8
	}
	if fixed {
		return size
	}
	if sizer.Fork() >= ssz.ForkFrontier {
		size += ssz.SizeDynamicBytes(sizer, obj.ExtraData)
	}
	size += ssz.SizeSliceOfDynamicBytes(sizer, obj.Transactions)
	if sizer.Fork() >= ssz.ForkShanghai {
		size += ssz.SizeSliceOfStaticObjects(sizer, obj.Withdrawals)
	}
	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *ExecutionPayloadMonolith2) DefineSSZ(codec *ssz.Codec) {
	// Define the static data (fields and dynamic offsets)
	ssz.DefineStaticBytes(codec, &obj.ParentHash)                                                                    // Field  ( 0) -    ParentHash -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.FeeRecipient)                                                                  // Field  ( 1) -  FeeRecipient -  20 bytes
	ssz.DefineStaticBytes(codec, &obj.StateRoot)                                                                     // Field  ( 2) -     StateRoot -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.ReceiptsRoot)                                                                  // Field  ( 3) -  ReceiptsRoot -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.LogsBloom)                                                                     // Field  ( 4) -     LogsBloom - 256 bytes
	ssz.DefineStaticBytes(codec, &obj.PrevRandao)                                                                    // Field  ( 5) -    PrevRandao -  32 bytes
	ssz.DefineUint64(codec, &obj.BlockNumber)                                                                        // Field  ( 6) -   BlockNumber -   8 bytes
	ssz.DefineUint64(codec, &obj.GasLimit)                                                                           // Field  ( 7) -      GasLimit -   8 bytes
	ssz.DefineUint64(codec, &obj.GasUsed)                                                                            // Field  ( 8) -       GasUsed -   8 bytes
	ssz.DefineUint64(codec, &obj.Timestamp)                                                                          // Field  ( 9) -     Timestamp -   8 bytes
	ssz.DefineDynamicBytesOffsetOnFork(codec, &obj.ExtraData, 32, ssz.ForkFilter{Added: ssz.ForkFrontier})           // Offset (10) -     ExtraData -   4 bytes
	ssz.DefineUint256BigIntOnFork(codec, &obj.BaseFeePerGas, ssz.ForkFilter{Added: ssz.ForkUnknown})                 // Field  (11) - BaseFeePerGas -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.BlockHash)                                                                     // Field  (12) -     BlockHash -  32 bytes
	ssz.DefineSliceOfDynamicBytesOffset(codec, &obj.Transactions, 1048576, 1073741824)                               // Offset (13) -  Transactions -   4 bytes
	ssz.DefineSliceOfStaticObjectsOffsetOnFork(codec, &obj.Withdrawals, 16, ssz.ForkFilter{Added: ssz.ForkShanghai}) // Offset (14) -   Withdrawals -   4 bytes
	ssz.DefineUint64PointerOnFork(codec, &obj.BlobGasUsed, ssz.ForkFilter{Added: ssz.ForkCancun})                    // Field  (15) -   BlobGasUsed -   8 bytes
	ssz.DefineUint64PointerOnFork(codec, &obj.ExcessBlobGas, ssz.ForkFilter{Added: ssz.ForkCancun})                  // Field  (16) - ExcessBlobGas -   8 bytes

	// Define the dynamic data (fields)
	ssz.DefineDynamicBytesContentOnFork(codec, &obj.ExtraData, 32, ssz.ForkFilter{Added: ssz.ForkFrontier})           // Field  (10) -     ExtraData - ? bytes
	ssz.DefineSliceOfDynamicBytesContent(codec, &obj.Transactions, 1048576, 1073741824)                               // Field  (13) -  Transactions - ? bytes
	ssz.DefineSliceOfStaticObjectsContentOnFork(codec, &obj.Withdrawals, 16, ssz.ForkFilter{Added: ssz.ForkShanghai}) // Field  (14) -   Withdrawals - ? bytes
}

// ClearSSZ zeroes out all fields of ExecutionPayloadMonolith2 for leftover decode.
func (obj *ExecutionPayloadMonolith2) ClearSSZ() {
	obj.ParentHash = [32]byte{}
	obj.FeeRecipient = [20]byte{}
	obj.StateRoot = [32]byte{}
	obj.ReceiptsRoot = [32]byte{}
	obj.LogsBloom = [256]byte{}
	obj.PrevRandao = [32]byte{}
	obj.BlockNumber = 0
	obj.GasLimit = 0
	obj.GasUsed = 0
	obj.Timestamp = 0
	obj.ExtraData = nil
	obj.BaseFeePerGas = nil
	obj.BlockHash = [32]byte{}
	obj.Transactions = nil
	obj.Withdrawals = nil
	obj.BlobGasUsed = nil
	obj.ExcessBlobGas = nil
}
