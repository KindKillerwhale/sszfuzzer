// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of Fork for leftover decode.
func (obj *Fork) ClearSSZ() {
	obj.PreviousVersion = [4]byte{}
	obj.CurrentVersion = [4]byte{}
	obj.Epoch = 0
}
