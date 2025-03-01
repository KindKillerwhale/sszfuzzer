// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// SizeSSZ returns the total size of the static ssz object.
func (obj *SingleFieldTestStruct) SizeSSZ(sizer *ssz.Sizer) uint32 {
	return 1
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *SingleFieldTestStruct) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineUint8(codec, &obj.A) // Field  (0) - A - 1 bytes
}

// ClearSSZ zeroes out all fields of SingleFieldTestStruct for leftover decode.
func (obj *SingleFieldTestStruct) ClearSSZ() {
	obj.A = 0
}
