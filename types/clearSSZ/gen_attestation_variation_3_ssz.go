// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package sszgen

// ClearSSZ zeroes out all fields of AttestationVariation3 for leftover decode.
func (obj *AttestationVariation3) ClearSSZ() {
	obj.AggregationBits = nil
	if obj.Data != nil {
		obj.Data.ClearSSZ()
	}
	obj.Signature = [96]byte{}
	obj.Future = nil
}
