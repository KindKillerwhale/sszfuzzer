// ssz: Go Simple Serialize (SSZ) codec library
// Copyright 2024 ssz Authors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"go/types"
)

type opset interface{}

type opsetStatic struct {
	clearStmt string // clear : snippet to clear (zero out) this static field
	bytes     []int  // bytes : list of byte offsets to clear
}

type opsetDynamic struct {
	clearStmt string // clear : snippet to clear dynamic field
}

func (p *parseContext) resolveBasicOpset(typ *types.Basic, tags *sizeTag, pointer bool) (opset, error) {
	if tags != nil {
		if tags.limit != nil {
			return nil, fmt.Errorf("basic type cannot have ssz-max tag")
		}
		if len(tags.size) != 1 {
			return nil, fmt.Errorf("basic type requires 1D ssz-size tag: have %v", tags.size)
		}
	}
	// Return the type-specific opsets
	switch typ.Kind() {
	case types.Bool:
		if tags != nil && tags.size[0] != 1 {
			return nil, fmt.Errorf("boolean basic type requires ssz-size=1: have %d", tags.size[0])
		}
		if !pointer {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = false",
			}, nil
		} else {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil
		}
	case types.Uint8:
		if tags != nil && tags.size[0] != 1 {
			return nil, fmt.Errorf("byte basic type requires ssz-size=1: have %d", tags.size[0])
		}
		if !pointer {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = 0",
			}, nil
		} else {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil
		}
	case types.Uint16:
		if tags != nil && tags.size[0] != 2 {
			return nil, fmt.Errorf("uint16 basic type requires ssz-size=2: have %d", tags.size[0])
		}
		if !pointer {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = 0",
			}, nil
		} else {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil
		}
	case types.Uint32:
		if tags != nil && tags.size[0] != 4 {
			return nil, fmt.Errorf("uint32 basic type requires ssz-size=4: have %d", tags.size[0])
		}
		if !pointer {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = 0",
			}, nil
		} else {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil
		}
	case types.Uint64:
		if tags != nil && tags.size[0] != 8 {
			return nil, fmt.Errorf("uint64 basic type requires ssz-size=8: have %d", tags.size[0])
		}
		if !pointer {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = 0",
			}, nil
		} else {
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil
		}
	default:
		return nil, fmt.Errorf("unsupported basic type: %s", typ)
	}
}

func (p *parseContext) resolveBitlistOpset(tags *sizeTag) (opset, error) {
	if tags == nil || tags.limit == nil {
		return nil, fmt.Errorf("slice of bits type requires ssz-max tag")
	}
	if len(tags.size) > 0 {
		return nil, fmt.Errorf("slice of bits type cannot have ssz-size tag")
	}
	if len(tags.limit) != 1 {
		return nil, fmt.Errorf("slice of bits tag conflict: field supports [N] bits, tag wants %v bits", tags.limit)
	}
	return &opsetDynamic{
		clearStmt: "o.{{.Field}} = nil", //or "o.{{.Field}} = o.{{.Field}}[:0]"
	}, nil
}

func (p *parseContext) resolveArrayOpset(typ types.Type, size int, tags *sizeTag, pointer bool) (opset, error) {
	switch typ := typ.(type) {

	case *types.Named:
		if _, ok := typ.Underlying().(*types.Array); ok {
			if pointer {
				clearStmt := fmt.Sprintf("o.{{.Field}} = nil // pointer to named array: %s", typ.Obj().Name())
				return &opsetStatic{
					clearStmt: clearStmt,
				}, nil
			} else {
				clearStmt := fmt.Sprintf("o.{{.Field}} = [%d]%s{}", size, typ.Obj().Name())

				return &opsetStatic{
					clearStmt: clearStmt,
					bytes:     []int{size},
				}, nil
			}
		}

		return p.resolveArrayOpset(typ.Underlying(), size, tags, pointer)

	case *types.Basic:
		// Sanity check a few tag constraints relevant for all arrays of basic types
		if tags != nil {
			if tags.limit != nil {
				return nil, fmt.Errorf("array of basic type cannot have ssz-max tag")
			}
		}
		switch typ.Kind() {
		case types.Byte:
			// If the byte array is a packet bitvector, handle is explicitly
			if tags != nil && tags.bits {
				if len(tags.size) != 1 || tags.size[0] < (size-1)*8+1 || tags.size[0] > size*8 {
					return nil, fmt.Errorf("array of bits tag conflict: field supports %d-%d bits, tag wants %v bits", (size-1)*8+1, size*8, tags.size)
				}

				if !pointer {
					clearStmt := fmt.Sprintf("o.{{.Field}} = [%d]byte{}", (tags.size[0]+7)/8)
					return &opsetStatic{
						clearStmt: clearStmt,
					}, nil
				} else {
					return &opsetStatic{
						clearStmt: "o.{{.Field}} = nil",
					}, nil
				}
			}
			// Not a bitvector, interpret as plain byte array
			if tags != nil {
				if (len(tags.size) != 1 && len(tags.size) != 2) ||
					(len(tags.size) == 1 && tags.size[0] != size) ||
					(len(tags.size) == 2 && (tags.size[0] != size || tags.size[1] != 1)) {
					return nil, fmt.Errorf("array of byte basic type tag conflict: field is %d bytes, tag wants %v bytes", size, tags.size)
				}
			}
			if !pointer {
				return &opsetStatic{
					clearStmt: "o.{{.Field}} = [{{.Size}}]byte{}",
					bytes:     []int{size},
				}, nil
			} else {
				return &opsetStatic{
					clearStmt: "o.{{.Field}} = nil",
				}, nil
			}

		case types.Uint64:
			if tags != nil {
				if (len(tags.size) != 1 && len(tags.size) != 2) ||
					(len(tags.size) == 1 && tags.size[0] != size) ||
					(len(tags.size) == 2 && (tags.size[0] != size || tags.size[1] != 8)) {
					return nil, fmt.Errorf("array of byte basic type tag conflict: field is %d bytes, tag wants %v bytes", size, tags.size)
				}
			}
			if !pointer {
				return &opsetStatic{
					clearStmt: "o.{{.Field}} = [{{.Size}}]uint64{}",
					bytes:     []int{size},
				}, nil
			} else {
				return &opsetStatic{
					clearStmt: "o.{{.Field}} = nil",
				}, nil
			}

		default:
			return nil, fmt.Errorf("unsupported array item basic type: %s", typ)
		}

	case *types.Array:
		return p.resolveArrayOfArrayOpset(typ.Elem(), size, int(typ.Len()), tags)

	default:
		return nil, fmt.Errorf("unsupported array item type: %s", typ)
	}
}

func (p *parseContext) resolveArrayOfArrayOpset(typ types.Type, outerSize, innerSize int, tags *sizeTag) (opset, error) {
	switch typ := typ.(type) {
	case *types.Named:
		if arr, ok := typ.Underlying().(*types.Array); ok {
			arrLen := int(arr.Len())

			if innerSize != arrLen {
				return nil, fmt.Errorf("named array %s mismatch: want innerSize=%d, actual %d", typ.Obj().Name(), innerSize, arr.Len())
			}

			return &opsetStatic{
				clearStmt: "o.{{.Field}} = [outerSize]" + typ.Obj().Name() + "{}",
				bytes:     []int{outerSize, int(arr.Len())},
			}, nil
		}

		return nil, fmt.Errorf("named type %s is not an array", typ.Obj().Name())

	case *types.Basic:
		// Sanity check a few tag constraints relevant for all arrays of basic types
		if tags != nil {
			if tags.limit != nil {
				return nil, fmt.Errorf("array of array of basic type cannot have ssz-max tag")
			}
		}
		switch typ.Kind() {
		case types.Byte:
			if tags != nil {
				if (len(tags.size) != 2 && len(tags.size) != 3) ||
					(len(tags.size) == 2 && (tags.size[0] != outerSize || tags.size[1] != innerSize)) ||
					(len(tags.size) == 3 && (tags.size[0] != outerSize || tags.size[1] != innerSize || tags.size[2] != 1)) {
					return nil, fmt.Errorf("array of array of byte basic type tag conflict: field is [%d, %d] bytes, tag wants %v bytes", outerSize, innerSize, tags.size)
				}
			}
			return &opsetStatic{
				clearStmt: "o.{{.Field}} = [outerSize][innerSize]byte{}",
				bytes:     []int{outerSize, innerSize},
			}, nil

		default:
			return nil, fmt.Errorf("unsupported array-of-array item basic type: %s", typ)
		}

	default:
		return nil, fmt.Errorf("unsupported array-of-array item type: %s", typ)
	}

}

func (p *parseContext) resolveSliceOpset(typ types.Type, tags *sizeTag) (opset, error) {
	// Sanity check a few tag constraints relevant for all slice types
	if tags == nil {
		return nil, fmt.Errorf("slice type requires ssz tags")
	}
	switch typ := typ.(type) {
	case *types.Basic:
		switch typ.Kind() {
		case types.Byte:
			// Slice of bytes. If we have ssz-size, it's a static slice
			if len(tags.size) > 0 {
				if (len(tags.size) != 1 && len(tags.size) != 2) ||
					(len(tags.size) == 2 && tags.size[1] != 1) {
					return nil, fmt.Errorf("static slice of byte basic type tag conflict: needs [N] or [N, 1] tag, has %v", tags.size)
				}
				if len(tags.limit) > 0 {
					return nil, fmt.Errorf("static slice of byte basic type cannot have ssz-max tag")
				}
				return &opsetStatic{
					clearStmt: "o.{{.Field}} = o.{{.Field}}[:0]",
				}, nil
			}
			// Not a static slice of bytes, we need to pull ssz-max for the limits
			if tags.limit == nil {
				return nil, fmt.Errorf("dynamic slice of byte basic type requires ssz-max tag")
			}
			if len(tags.limit) != 1 {
				return nil, fmt.Errorf("dynamic slice of byte basic type tag conflict: needs [N] tag, has %v", tags.limit)
			}
			return &opsetDynamic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil

		case types.Uint64:
			// Slice of uint64s. If we have ssz-size, it's a static slice
			if len(tags.size) > 0 {
				if (len(tags.size) != 1 && len(tags.size) != 2) ||
					(len(tags.size) == 2 && tags.size[1] != 8) {
					return nil, fmt.Errorf("static slice of uint64 basic type tag conflict: needs [N] or [N, 8] tag, has %v", tags.size)
				}
				if len(tags.limit) > 0 {
					return nil, fmt.Errorf("static slice of uint64 basic type cannot have ssz-max tag")
				}
				return &opsetStatic{
					clearStmt: "o.{{.Field}} = o.{{.Field}}[:0]",
				}, nil
			}
			// Not a static slice of bytes, we need to pull ssz-max for the limits
			if tags.limit == nil {
				return nil, fmt.Errorf("dynamic slice of uint64 basic type requires ssz-max tag")
			}
			if len(tags.limit) != 1 {
				return nil, fmt.Errorf("dynamic slice of uint64 basic type tag conflict: needs [N] tag, has %v", tags.limit)
			}
			return &opsetDynamic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil

		default:
			return nil, fmt.Errorf("unsupported slice item basic type: %s", typ)
		}
	case *types.Pointer:
		if hasClearSSZMethod(typ.Elem()) {
			clearSnippet := `for i := range obj.{{.Field}} {
				if obj.{{.Field}}[i] != nil {
					obj.{{.Field}}[i].ClearSSZ()
				}
			}`

			return &opsetDynamic{
				clearStmt: clearSnippet,
			}, nil
		}
		// return nil, fmt.Errorf("unsupported pointer slice item type %s", typ.String())
		return &opsetDynamic{
			clearStmt: "obj.{{.Field}} = nil",
		}, nil

	case *types.Array:
		return p.resolveSliceOfArrayOpset(typ.Elem(), int(typ.Len()), tags)

	case *types.Slice:
		return p.resolveSliceOfSliceOpset(typ.Elem(), tags)

	case *types.Named:
		return p.resolveSliceOpset(typ.Underlying(), tags)

	default:
		return nil, fmt.Errorf("unsupported slice item type: %s", typ)
	}
}

func (p *parseContext) resolveSliceOfArrayOpset(typ types.Type, innerSize int, tags *sizeTag) (opset, error) {
	switch typ := typ.(type) {
	case *types.Basic:
		switch typ.Kind() {
		case types.Byte:
			// Slice of array of bytes. If we have ssz-size, it's a static slice.
			if len(tags.size) > 0 {
				if (len(tags.size) != 1 && len(tags.size) != 2) ||
					(len(tags.size) == 2 && tags.size[1] != innerSize) {
					return nil, fmt.Errorf("static slice of array of byte basic type tag conflict: needs [N] or [N, %d] tag, has %v", innerSize, tags.size)
				}
				if len(tags.limit) > 0 {
					return nil, fmt.Errorf("static slice of array of byte basic type cannot have ssz-max tag")
				}
				return &opsetStatic{
					clearStmt: "o.{{.Field}} = o.{{.Field}}[:0]",
				}, nil
			}
			// Not a static slice of array of bytes, we need to pull ssz-max for the limits
			if tags.limit == nil {
				return nil, fmt.Errorf("dynamic slice of array of byte basic type requires ssz-max tag")
			}
			if len(tags.limit) != 1 {
				return nil, fmt.Errorf("dynamic slice of array of byte basic type tag conflict: needs [N] tag, has %v", tags.limit)
			}
			return &opsetDynamic{
				clearStmt: "o.{{.Field}} = nil",
			}, nil
		default:
			return nil, fmt.Errorf("unsupported array-of-array item basic type: %s", typ)
		}
	default:
		return nil, fmt.Errorf("unsupported array-of-array item type: %s", typ)
	}
}

func (p *parseContext) resolveSliceOfSliceOpset(typ types.Type, tags *sizeTag) (*opsetDynamic, error) {
	switch typ := typ.(type) {
	case *types.Basic:
		switch typ.Kind() {
		case types.Byte:
			// Slice of slice of bytes. At this point we have 2D possibilities of
			// ssz-size and ssz-max combinations, each resulting in a different
			// call that we have to make. Reject any conflicts in the tags, after
			// which assemble the required combo.
			switch {
			case len(tags.size) > 0 && len(tags.limit) == 0:
				return nil, fmt.Errorf("static slice of static slice of bytes not implemented yet")

			case len(tags.size) == 0 && len(tags.limit) > 0:
				if len(tags.limit) != 2 {
					return nil, fmt.Errorf("dynamic slice of dynamic slice of byte basic type tag conflict: needs [N, M] ssz-max tag, has %v", tags.limit)
				}
				return &opsetDynamic{
					clearStmt: "o.{{.Field}} = nil",
				}, nil

			default:
				return nil, fmt.Errorf("not implemented yet")
			}
		default:
			return nil, fmt.Errorf("unsupported slice-of-slice item basic type: %s", typ)
		}
	default:
		return nil, fmt.Errorf("unsupported slice-of-slice item type: %s", typ)
	}
}

func (p *parseContext) resolvePointerOpset(typ *types.Pointer, tags *sizeTag) (opset, error) {
	if isUint256(typ.Elem()) {
		if tags != nil {
			if tags.limit != nil {
				return nil, fmt.Errorf("uint256 basic type cannot have ssz-max tag")
			}
			if len(tags.size) != 1 || tags.size[0] != 32 {
				return nil, fmt.Errorf("uint256 basic type tag conflict: field is [32] bytes, tag wants %v", tags.size)
			}
		}
		return &opsetStatic{
			clearStmt: "o.{{.Field}} = nil",
		}, nil
	}
	if isBigInt(typ.Elem()) {
		if tags != nil {
			if tags.limit != nil {
				return nil, fmt.Errorf("big.Int (uint256) basic type cannot have ssz-max tag")
			}
			if len(tags.size) != 1 || tags.size[0] != 32 {
				return nil, fmt.Errorf("big.Int (uint256) basic type tag conflict: field is [32] bytes, tag wants %v", tags.size)
			}
		}
		return &opsetStatic{
			clearStmt: "o.{{.Field}} = nil",
		}, nil
	}

	if hasClearSSZMethod(typ.Elem()) {
		if tags != nil {
			return nil, fmt.Errorf("dynamic object type cannot have any ssz tags")
		}
		return &opsetDynamic{
			clearStmt: "if o.{{.Field}} != nil {o.{{.Field}}.ClearSSZ()}",
		}, nil
	}

	named, ok := typ.Elem().(*types.Named)
	if !ok {
		return nil, fmt.Errorf("unsupported pointer type %s", typ.String())
	}

	if _, isStruct := named.Underlying().(*types.Struct); isStruct {
		return &opsetStatic{
			clearStmt: "if o.{{.Field}} != nil {o.{{.Field}}.ClearSSZ()}",
		}, nil
	}

	return p.resolveOpset(named.Underlying(), tags, true)
}

func hasClearSSZMethod(typ types.Type) bool {
	named, ok := typ.(*types.Named)
	if !ok {
		return false
	}

	for i := 0; i < named.NumMethods(); i++ {
		method := named.Method(i)
		if method.Name() == "ClearSSZ" {
			if _, ok := method.Type().(*types.Signature); ok {
				return true
			}
		}
	}
	return false
}
