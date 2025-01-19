// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of AggregateAndProof for leftover decode.
func (obj *AggregateAndProof) ClearSSZ() {
	obj.Index = 0
	if obj.Aggregate != nil {
		obj.Aggregate.ClearSSZ()
	}
	obj.SelectionProof = [96]byte{}
}
