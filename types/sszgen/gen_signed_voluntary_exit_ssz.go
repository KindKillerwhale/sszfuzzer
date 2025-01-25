// Code generated by merging. DO NOT EDIT.
package sszgen

import "github.com/karalabe/ssz"

// Cached static size computed on package init.
var staticSizeCacheSignedVoluntaryExit = ssz.PrecomputeStaticSizeCache((*SignedVoluntaryExit)(nil))

// SizeSSZ returns the total size of the static ssz object.
func (obj *SignedVoluntaryExit) SizeSSZ(sizer *ssz.Sizer) (size uint32) {
	if fork := int(sizer.Fork()); fork < len(staticSizeCacheSignedVoluntaryExit) {
		return staticSizeCacheSignedVoluntaryExit[fork]
	}
	size = (*VoluntaryExit)(nil).SizeSSZ(sizer) + 96
	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *SignedVoluntaryExit) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineStaticObject(codec, &obj.Exit)     // Field  (0) -      Exit -  ? bytes (VoluntaryExit)
	ssz.DefineStaticBytes(codec, &obj.Signature) // Field  (1) - Signature - 96 bytes
}

// ClearSSZ zeroes out all fields of SignedVoluntaryExit for leftover decode.
func (obj *SignedVoluntaryExit) ClearSSZ() {
	if obj.Exit != nil {
		obj.Exit.ClearSSZ()
	}
	obj.Signature = [96]byte{}
}
