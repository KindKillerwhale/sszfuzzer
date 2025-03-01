// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// Cached static size computed on package init.
var staticSizeCacheAttestationData = ssz.PrecomputeStaticSizeCache((*AttestationData)(nil))

// SizeSSZ returns the total size of the static ssz object.
func (obj *AttestationData) SizeSSZ(sizer *ssz.Sizer) (size uint32) {
	if fork := int(sizer.Fork()); fork < len(staticSizeCacheAttestationData) {
		return staticSizeCacheAttestationData[fork]
	}
	size = 8 + 8 + 32 + (*Checkpoint)(nil).SizeSSZ(sizer) + (*Checkpoint)(nil).SizeSSZ(sizer)
	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *AttestationData) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineUint64(codec, &obj.Slot)                 // Field  (0) -            Slot -  8 bytes
	ssz.DefineUint64(codec, &obj.Index)                // Field  (1) -           Index -  8 bytes
	ssz.DefineStaticBytes(codec, &obj.BeaconBlockHash) // Field  (2) - BeaconBlockHash - 32 bytes
	ssz.DefineStaticObject(codec, &obj.Source)         // Field  (3) -          Source -  ? bytes (Checkpoint)
	ssz.DefineStaticObject(codec, &obj.Target)         // Field  (4) -          Target -  ? bytes (Checkpoint)
}

// ClearSSZ zeroes out all fields of AttestationData for leftover decode.
func (obj *AttestationData) ClearSSZ() {
	obj.Slot = 0
	obj.Index = 0
	obj.BeaconBlockHash = [32]byte{}
	if obj.Source != nil {
		obj.Source.ClearSSZ()
	}
	if obj.Target != nil {
		obj.Target.ClearSSZ()
	}
}
