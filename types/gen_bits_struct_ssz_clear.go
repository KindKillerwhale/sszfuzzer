// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of BitsStruct for leftover decode.
func (obj *BitsStruct) ClearSSZ() {
	obj.A = nil
	obj.B = [1]byte{}
	obj.C = [1]byte{}
	obj.D = nil
	obj.E = [1]byte{}
}
