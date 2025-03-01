// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// SizeSSZ returns the total size of the static ssz object.
func (obj *Fork) SizeSSZ(sizer *ssz.Sizer) uint32 {
	return 4 + 4 + 8
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *Fork) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineStaticBytes(codec, &obj.PreviousVersion) // Field  (0) - PreviousVersion - 4 bytes
	ssz.DefineStaticBytes(codec, &obj.CurrentVersion)  // Field  (1) -  CurrentVersion - 4 bytes
	ssz.DefineUint64(codec, &obj.Epoch)                // Field  (2) -           Epoch - 8 bytes
}

// ClearSSZ zeroes out all fields of Fork for leftover decode.
func (obj *Fork) ClearSSZ() {
	obj.PreviousVersion = [4]byte{}
	obj.CurrentVersion = [4]byte{}
	obj.Epoch = 0
}
