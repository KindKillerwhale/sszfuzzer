// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of VoluntaryExit for leftover decode.
func (obj *VoluntaryExit) ClearSSZ() {
	obj.Epoch = 0
	obj.ValidatorIndex = 0
}
