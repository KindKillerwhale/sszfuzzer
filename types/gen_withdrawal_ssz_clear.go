// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of Withdrawal for leftover decode.
func (obj *Withdrawal) ClearSSZ() {
	obj.Index = 0
	obj.Validator = 0
	obj.Address = [20]byte{}
	obj.Amount = 0
}
