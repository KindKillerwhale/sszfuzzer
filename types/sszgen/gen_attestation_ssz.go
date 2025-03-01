// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// Cached static size computed on package init.
var staticSizeCacheAttestation = ssz.PrecomputeStaticSizeCache((*Attestation)(nil))

// SizeSSZ returns either the static size of the object if fixed == true, or
// the total size otherwise.
func (obj *Attestation) SizeSSZ(sizer *ssz.Sizer, fixed bool) (size uint32) {
	// Load static size if already precomputed, calculate otherwise
	if fork := int(sizer.Fork()); fork < len(staticSizeCacheAttestation) {
		size = staticSizeCacheAttestation[fork]
	} else {
		size = 4 + (*AttestationData)(nil).SizeSSZ(sizer) + 96
	}
	// Either return the static size or accumulate the dynamic too
	if fixed {
		return size
	}
	size += ssz.SizeSliceOfBits(sizer, obj.AggregationBits)

	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *Attestation) DefineSSZ(codec *ssz.Codec) {
	// Define the static data (fields and dynamic offsets)
	ssz.DefineSliceOfBitsOffset(codec, &obj.AggregationBits, 2048) // Offset (0) - AggregationBits -  4 bytes
	ssz.DefineStaticObject(codec, &obj.Data)                       // Field  (1) -            Data -  ? bytes (AttestationData)
	ssz.DefineStaticBytes(codec, &obj.Signature)                   // Field  (2) -       Signature - 96 bytes

	// Define the dynamic data (fields)
	ssz.DefineSliceOfBitsContent(codec, &obj.AggregationBits, 2048) // Field  (0) - AggregationBits - ? bytes
}

// ClearSSZ zeroes out all fields of Attestation for leftover decode.
func (obj *Attestation) ClearSSZ() {
	obj.AggregationBits = nil
	if obj.Data != nil {
		obj.Data.ClearSSZ()
	}
	obj.Signature = [96]byte{}
}
