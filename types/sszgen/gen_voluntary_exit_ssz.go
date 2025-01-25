// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// SizeSSZ returns the total size of the static ssz object.
func (obj *VoluntaryExit) SizeSSZ(sizer *ssz.Sizer) uint32 {
	return 8 + 8
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *VoluntaryExit) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineUint64(codec, &obj.Epoch)          // Field  (0) -          Epoch - 8 bytes
	ssz.DefineUint64(codec, &obj.ValidatorIndex) // Field  (1) - ValidatorIndex - 8 bytes
}

// ClearSSZ zeroes out all fields of VoluntaryExit for leftover decode.
func (obj *VoluntaryExit) ClearSSZ() {
	obj.Epoch = 0
	obj.ValidatorIndex = 0
}
