// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package sszgen

// ClearSSZ zeroes out all fields of IndexedAttestation for leftover decode.
func (obj *IndexedAttestation) ClearSSZ() {
	obj.AttestationIndices = nil
	if obj.Data != nil {
		obj.Data.ClearSSZ()
	}
	obj.Signature = [96]byte{}
}
