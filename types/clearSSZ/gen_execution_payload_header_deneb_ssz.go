// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package sszgen

// ClearSSZ zeroes out all fields of ExecutionPayloadHeaderDeneb for leftover decode.
func (obj *ExecutionPayloadHeaderDeneb) ClearSSZ() {
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
	obj.BaseFeePerGas = [32]byte{}
	obj.BlockHash = [32]byte{}
	obj.TransactionsRoot = [32]byte{}
	obj.WithdrawalRoot = [32]byte{}
	obj.BlobGasUsed = 0
	obj.ExcessBlobGas = 0
}
