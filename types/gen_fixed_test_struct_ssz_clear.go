// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of FixedTestStruct for leftover decode.
func (obj *FixedTestStruct) ClearSSZ() {
	obj.A = 0
	obj.B = 0
	obj.C = 0
}
