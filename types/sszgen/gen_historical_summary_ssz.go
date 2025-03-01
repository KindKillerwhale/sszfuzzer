// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// SizeSSZ returns the total size of the static ssz object.
func (obj *HistoricalSummary) SizeSSZ(sizer *ssz.Sizer) uint32 {
	return 32 + 32
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *HistoricalSummary) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineStaticBytes(codec, &obj.BlockSummaryRoot) // Field  (0) - BlockSummaryRoot - 32 bytes
	ssz.DefineStaticBytes(codec, &obj.StateSummaryRoot) // Field  (1) - StateSummaryRoot - 32 bytes
}

// ClearSSZ zeroes out all fields of HistoricalSummary for leftover decode.
func (obj *HistoricalSummary) ClearSSZ() {
	obj.BlockSummaryRoot = [32]byte{}
	obj.StateSummaryRoot = [32]byte{}
}
