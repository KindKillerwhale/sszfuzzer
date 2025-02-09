// ssz: Go Simple Serialize (SSZ) codec library
// Copyright 2024 ssz Authors
// SPDX-License-Identifier: BSD-3-Clause

package sszgen

import "github.com/prysmaticlabs/go-bitfield"

//go:generate go run ../cmd/sszgen_clear -type SingleFieldTestStruct -out clearSSZ/gen_single_field_test_struct_ssz.go
//go:generate go run ../cmd/sszgen_clear -type SmallTestStruct -out clearSSZ/gen_small_test_struct_ssz.go
//go:generate go run ../cmd/sszgen_clear -type FixedTestStruct -out clearSSZ/gen_fixed_test_struct_ssz.go
//go:generate go run ../cmd/sszgen_clear -type BitsStruct -out clearSSZ/gen_bits_struct_ssz.go

type SingleFieldTestStruct struct {
	A byte
}

type SmallTestStruct struct {
	A uint16
	B uint16
}

type FixedTestStruct struct {
	A uint8
	B uint64
	C uint32
}

type BitsStruct struct {
	A bitfield.Bitlist `ssz-max:"5"`
	B [1]byte          `ssz-size:"2" ssz:"bits"`
	C [1]byte          `ssz-size:"1" ssz:"bits"`
	D bitfield.Bitlist `ssz-max:"6"`
	E [1]byte          `ssz-size:"8" ssz:"bits"`
}
