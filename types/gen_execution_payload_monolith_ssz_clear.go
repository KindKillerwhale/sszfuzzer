// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of ExecutionPayloadMonolith for leftover decode.
func (obj *ExecutionPayloadMonolith) ClearSSZ() {
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
	for i := range obj.Withdrawals {
		if obj.Withdrawals[i] != nil {
			obj.Withdrawals[i].ClearSSZ()
		}
	}
	obj.BlobGasUsed = nil
	obj.ExcessBlobGas = nil
}
