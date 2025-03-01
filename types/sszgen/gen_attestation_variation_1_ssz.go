// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// Cached static size computed on package init.
var staticSizeCacheAttestationVariation1 = ssz.PrecomputeStaticSizeCache((*AttestationVariation1)(nil))

// SizeSSZ returns either the static size of the object if fixed == true, or
// the total size otherwise.
func (obj *AttestationVariation1) SizeSSZ(sizer *ssz.Sizer, fixed bool) (size uint32) {
	// Load static size if already precomputed, calculate otherwise
	if fork := int(sizer.Fork()); fork < len(staticSizeCacheAttestationVariation1) {
		size = staticSizeCacheAttestationVariation1[fork]
	} else {
		if sizer.Fork() >= ssz.ForkFuture {
			size += 8
		}
		size += 4 + (*AttestationData)(nil).SizeSSZ(sizer) + 96
	}
	// Either return the static size or accumulate the dynamic too
	if fixed {
		return size
	}
	size += ssz.SizeSliceOfBits(sizer, obj.AggregationBits)

	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *AttestationVariation1) DefineSSZ(codec *ssz.Codec) {
	// Define the static data (fields and dynamic offsets)
	ssz.DefineUint64PointerOnFork(codec, &obj.Future, ssz.ForkFilter{Added: ssz.ForkFuture}) // Field  (0) -          Future -  8 bytes
	ssz.DefineSliceOfBitsOffset(codec, &obj.AggregationBits, 2048)                           // Offset (1) - AggregationBits -  4 bytes
	ssz.DefineStaticObject(codec, &obj.Data)                                                 // Field  (2) -            Data -  ? bytes (AttestationData)
	ssz.DefineStaticBytes(codec, &obj.Signature)                                             // Field  (3) -       Signature - 96 bytes

	// Define the dynamic data (fields)
	ssz.DefineSliceOfBitsContent(codec, &obj.AggregationBits, 2048) // Field  (1) - AggregationBits - ? bytes
}

// ClearSSZ zeroes out all fields of AttestationVariation1 for leftover decode.
func (obj *AttestationVariation1) ClearSSZ() {
	obj.Future = nil
	obj.AggregationBits = nil
	if obj.Data != nil {
		obj.Data.ClearSSZ()
	}
	obj.Signature = [96]byte{}
}
