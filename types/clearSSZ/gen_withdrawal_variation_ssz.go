// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package sszgen

// ClearSSZ zeroes out all fields of WithdrawalVariation for leftover decode.
func (obj *WithdrawalVariation) ClearSSZ() {
	obj.Index = 0
	obj.Validator = 0
	obj.Address = obj.Address[:0]
	obj.Amount = 0
}
