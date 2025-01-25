// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

import "github.com/karalabe/ssz"

// Cached static size computed on package init.
var staticSizeCacheAttestationVariation3 = ssz.PrecomputeStaticSizeCache((*AttestationVariation3)(nil))

// SizeSSZ returns either the static size of the object if fixed == true, or
// the total size otherwise.
func (obj *AttestationVariation3) SizeSSZ(sizer *ssz.Sizer, fixed bool) (size uint32) {
	// Load static size if already precomputed, calculate otherwise
	if fork := int(sizer.Fork()); fork < len(staticSizeCacheAttestationVariation3) {
		size = staticSizeCacheAttestationVariation3[fork]
	} else {
		size = 4 + (*AttestationData)(nil).SizeSSZ(sizer) + 96
		if sizer.Fork() >= ssz.ForkFuture {
			size += 8
		}
	}
	// Either return the static size or accumulate the dynamic too
	if fixed {
		return size
	}
	size += ssz.SizeSliceOfBits(sizer, obj.AggregationBits)

	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *AttestationVariation3) DefineSSZ(codec *ssz.Codec) {
	// Define the static data (fields and dynamic offsets)
	ssz.DefineSliceOfBitsOffset(codec, &obj.AggregationBits, 2048)                           // Offset (0) - AggregationBits -  4 bytes
	ssz.DefineStaticObject(codec, &obj.Data)                                                 // Field  (1) -            Data -  ? bytes (AttestationData)
	ssz.DefineStaticBytes(codec, &obj.Signature)                                             // Field  (2) -       Signature - 96 bytes
	ssz.DefineUint64PointerOnFork(codec, &obj.Future, ssz.ForkFilter{Added: ssz.ForkFuture}) // Field  (3) -          Future -  8 bytes

	// Define the dynamic data (fields)
	ssz.DefineSliceOfBitsContent(codec, &obj.AggregationBits, 2048) // Field  (0) - AggregationBits - ? bytes
}
