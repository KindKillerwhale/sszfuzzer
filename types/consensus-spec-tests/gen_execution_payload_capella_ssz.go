// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

import "github.com/karalabe/ssz"

// SizeSSZ returns either the static size of the object if fixed == true, or
// the total size otherwise.
func (obj *ExecutionPayloadCapella) SizeSSZ(sizer *ssz.Sizer, fixed bool) (size uint32) {
	size = 32 + 20 + 32 + 32 + 256 + 32 + 8 + 8 + 8 + 8 + 4 + 32 + 32 + 4 + 4
	if fixed {
		return size
	}
	size += ssz.SizeDynamicBytes(sizer, obj.ExtraData)
	size += ssz.SizeSliceOfDynamicBytes(sizer, obj.Transactions)
	size += ssz.SizeSliceOfStaticObjects(sizer, obj.Withdrawals)

	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *ExecutionPayloadCapella) DefineSSZ(codec *ssz.Codec) {
	// Define the static data (fields and dynamic offsets)
	ssz.DefineStaticBytes(codec, &obj.ParentHash)                                      // Field  ( 0) -    ParentHash -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.FeeRecipient)                                    // Field  ( 1) -  FeeRecipient -  20 bytes
	ssz.DefineStaticBytes(codec, &obj.StateRoot)                                       // Field  ( 2) -     StateRoot -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.ReceiptsRoot)                                    // Field  ( 3) -  ReceiptsRoot -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.LogsBloom)                                       // Field  ( 4) -     LogsBloom - 256 bytes
	ssz.DefineStaticBytes(codec, &obj.PrevRandao)                                      // Field  ( 5) -    PrevRandao -  32 bytes
	ssz.DefineUint64(codec, &obj.BlockNumber)                                          // Field  ( 6) -   BlockNumber -   8 bytes
	ssz.DefineUint64(codec, &obj.GasLimit)                                             // Field  ( 7) -      GasLimit -   8 bytes
	ssz.DefineUint64(codec, &obj.GasUsed)                                              // Field  ( 8) -       GasUsed -   8 bytes
	ssz.DefineUint64(codec, &obj.Timestamp)                                            // Field  ( 9) -     Timestamp -   8 bytes
	ssz.DefineDynamicBytesOffset(codec, &obj.ExtraData, 32)                            // Offset (10) -     ExtraData -   4 bytes
	ssz.DefineUint256(codec, &obj.BaseFeePerGas)                                       // Field  (11) - BaseFeePerGas -  32 bytes
	ssz.DefineStaticBytes(codec, &obj.BlockHash)                                       // Field  (12) -     BlockHash -  32 bytes
	ssz.DefineSliceOfDynamicBytesOffset(codec, &obj.Transactions, 1048576, 1073741824) // Offset (13) -  Transactions -   4 bytes
	ssz.DefineSliceOfStaticObjectsOffset(codec, &obj.Withdrawals, 16)                  // Offset (14) -   Withdrawals -   4 bytes

	// Define the dynamic data (fields)
	ssz.DefineDynamicBytesContent(codec, &obj.ExtraData, 32)                            // Field  (10) -     ExtraData - ? bytes
	ssz.DefineSliceOfDynamicBytesContent(codec, &obj.Transactions, 1048576, 1073741824) // Field  (13) -  Transactions - ? bytes
	ssz.DefineSliceOfStaticObjectsContent(codec, &obj.Withdrawals, 16)                  // Field  (14) -   Withdrawals - ? bytes
}
