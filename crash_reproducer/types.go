package main

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	sszgen "github.com/KindKillerwhale/sszfuzzer/types/sszgen"
	"github.com/google/go-cmp/cmp"
	kssz "github.com/karalabe/ssz"

	fastssz "github.com/KindKillerwhale/sszfuzzer/types/fastssz"
	fssz "github.com/ferranbt/fastssz"

	"github.com/holiman/uint256"
)

//------------------------------------------------------------------------------------
// (1) Karalabe object creation
//------------------------------------------------------------------------------------

// createKaralabeObjectByName returns a karalabe/ssz object by typeName.
func createKaralabeObjectByName(typeName string) (kssz.Object, error) {
	switch typeName {
	case "SingleFieldTestStruct":
		return new(sszgen.SingleFieldTestStruct), nil
	case "SmallTestStruct":
		return new(sszgen.SmallTestStruct), nil
	case "FixedTestStruct":
		return new(sszgen.FixedTestStruct), nil
	case "BitsStruct":
		return new(sszgen.BitsStruct), nil
	case "Checkpoint":
		return new(sszgen.Checkpoint), nil
	case "AttestationData":
		return new(sszgen.AttestationData), nil
	case "BeaconBlockHeader":
		return new(sszgen.BeaconBlockHeader), nil
	case "BLSToExecutionChange":
		return new(sszgen.BLSToExecutionChange), nil
	case "Attestation":
		return new(sszgen.Attestation), nil
	case "AggregateAndProof":
		return new(sszgen.AggregateAndProof), nil
	case "DepositData":
		return new(sszgen.DepositData), nil
	case "DepositMessage":
		return new(sszgen.DepositMessage), nil
	case "Deposit":
		return new(sszgen.Deposit), nil
	case "Eth1Block":
		return new(sszgen.Eth1Block), nil
	case "Eth1Data":
		return new(sszgen.Eth1Data), nil
	case "ExecutionPayload":
		return new(sszgen.ExecutionPayload), nil
	case "ExecutionPayloadHeader":
		return new(sszgen.ExecutionPayloadHeader), nil
	case "Fork":
		return new(sszgen.Fork), nil
	case "HistoricalBatch":
		return new(sszgen.HistoricalBatch), nil
	case "HistoricalSummary":
		return new(sszgen.HistoricalSummary), nil
	case "IndexedAttestation":
		return new(sszgen.IndexedAttestation), nil
	case "AttesterSlashing":
		return new(sszgen.AttesterSlashing), nil
	case "PendingAttestation":
		return new(sszgen.PendingAttestation), nil
	case "SignedBeaconBlockHeader":
		return new(sszgen.SignedBeaconBlockHeader), nil
	case "ProposerSlashing":
		return new(sszgen.ProposerSlashing), nil
	case "SignedBLSToExecutionChange":
		return new(sszgen.SignedBLSToExecutionChange), nil
	case "SyncAggregate":
		return new(sszgen.SyncAggregate), nil
	case "SyncCommittee":
		return new(sszgen.SyncCommittee), nil
	case "VoluntaryExit":
		return new(sszgen.VoluntaryExit), nil
	case "SignedVoluntaryExit":
		return new(sszgen.SignedVoluntaryExit), nil
	case "Validator":
		return new(sszgen.Validator), nil
	case "Withdrawal":
		return new(sszgen.Withdrawal), nil
	case "ExecutionPayloadCapella":
		return new(sszgen.ExecutionPayloadCapella), nil
	case "ExecutionPayloadHeaderCapella":
		return new(sszgen.ExecutionPayloadHeaderCapella), nil
	case "ExecutionPayloadDeneb":
		return new(sszgen.ExecutionPayloadDeneb), nil
	case "ExecutionPayloadHeaderDeneb":
		return new(sszgen.ExecutionPayloadHeaderDeneb), nil
	case "BeaconState":
		return new(sszgen.BeaconState), nil
	case "BeaconStateAltair":
		return new(sszgen.BeaconStateAltair), nil
	case "BeaconStateBellatrix":
		return new(sszgen.BeaconStateBellatrix), nil
	case "BeaconStateCapella":
		return new(sszgen.BeaconStateCapella), nil
	case "BeaconStateDeneb":
		return new(sszgen.BeaconStateDeneb), nil
	case "BeaconBlockBody":
		return new(sszgen.BeaconBlockBody), nil
	case "BeaconBlockBodyAltair":
		return new(sszgen.BeaconBlockBodyAltair), nil
	case "BeaconBlockBodyBellatrix":
		return new(sszgen.BeaconBlockBodyBellatrix), nil
	case "BeaconBlockBodyCapella":
		return new(sszgen.BeaconBlockBodyCapella), nil
	case "BeaconBlockBodyDeneb":
		return new(sszgen.BeaconBlockBodyDeneb), nil
	case "BeaconBlock":
		return new(sszgen.BeaconBlock), nil
	case "SingleFieldTestStructMonolith":
		return new(sszgen.SingleFieldTestStructMonolith), nil
	case "SmallTestStructMonolith":
		return new(sszgen.SmallTestStructMonolith), nil
	case "FixedTestStructMonolith":
		return new(sszgen.FixedTestStructMonolith), nil
	case "BitsStructMonolith":
		return new(sszgen.BitsStructMonolith), nil
	case "ExecutionPayloadMonolith":
		return new(sszgen.ExecutionPayloadMonolith), nil
	case "ExecutionPayloadMonolith2":
		return new(sszgen.ExecutionPayloadMonolith2), nil
	case "ExecutionPayloadHeaderMonolith":
		return new(sszgen.ExecutionPayloadHeaderMonolith), nil
	case "BeaconBlockBodyMonolith":
		return new(sszgen.BeaconBlockBodyMonolith), nil
	case "BeaconStateMonolith":
		return new(sszgen.BeaconStateMonolith), nil
	case "ValidatorMonolith":
		return new(sszgen.ValidatorMonolith), nil
	case "WithdrawalVariation":
		return new(sszgen.WithdrawalVariation), nil
	case "HistoricalBatchVariation":
		return new(sszgen.HistoricalBatchVariation), nil
	case "ExecutionPayloadVariation":
		return new(sszgen.ExecutionPayloadVariation), nil
	case "AttestationVariation1":
		return new(sszgen.AttestationVariation1), nil
	case "AttestationVariation2":
		return new(sszgen.AttestationVariation2), nil
	case "AttestationVariation3":
		return new(sszgen.AttestationVariation3), nil
	case "AttestationDataVariation1":
		return new(sszgen.AttestationDataVariation1), nil
	case "AttestationDataVariation2":
		return new(sszgen.AttestationDataVariation2), nil
	case "AttestationDataVariation3":
		return new(sszgen.AttestationDataVariation3), nil
	}
	return nil, fmt.Errorf("unknown karalabe type name: %s", typeName)
}

//------------------------------------------------------------------------------------
// (2) Fastssz object creation
//------------------------------------------------------------------------------------

// Object = fssz.Marshaler + fssz.Unmarshaler + fssz.HashRoot
type Object interface {
	fssz.Marshaler
	fssz.Unmarshaler
	fssz.HashRoot
}

// fastsszFactoryMapping returns a fastssz object by typeName.
var fastsszFactoryMapping = map[string]func() Object{
	"SingleFieldTestStruct":          func() Object { return &fastssz.SingleFieldTestStruct{} },
	"SmallTestStruct":                func() Object { return &fastssz.SmallTestStruct{} },
	"FixedTestStruct":                func() Object { return &fastssz.FixedTestStruct{} },
	"BitsStruct":                     func() Object { return &fastssz.BitsStruct{} },
	"Checkpoint":                     func() Object { return &fastssz.Checkpoint{} },
	"AttestationData":                func() Object { return &fastssz.AttestationData{} },
	"BeaconBlockHeader":              func() Object { return &fastssz.BeaconBlockHeader{} },
	"BLSToExecutionChange":           func() Object { return &fastssz.BLSToExecutionChange{} },
	"Attestation":                    func() Object { return &fastssz.Attestation{} },
	"AggregateAndProof":              func() Object { return &fastssz.AggregateAndProof{} },
	"DepositData":                    func() Object { return &fastssz.DepositData{} },
	"DepositMessage":                 func() Object { return &fastssz.DepositMessage{} },
	"Deposit":                        func() Object { return &fastssz.Deposit{} },
	"Eth1Block":                      func() Object { return &fastssz.Eth1Block{} },
	"Eth1Data":                       func() Object { return &fastssz.Eth1Data{} },
	"ExecutionPayload":               func() Object { return &fastssz.ExecutionPayload{} },
	"ExecutionPayloadHeader":         func() Object { return &fastssz.ExecutionPayloadHeader{} },
	"Fork":                           func() Object { return &fastssz.Fork{} },
	"HistoricalBatch":                func() Object { return &fastssz.HistoricalBatch{} },
	"HistoricalSummary":              func() Object { return &fastssz.HistoricalSummary{} },
	"IndexedAttestation":             func() Object { return &fastssz.IndexedAttestation{} },
	"AttesterSlashing":               func() Object { return &fastssz.AttesterSlashing{} },
	"PendingAttestation":             func() Object { return &fastssz.PendingAttestation{} },
	"SignedBeaconBlockHeader":        func() Object { return &fastssz.SignedBeaconBlockHeader{} },
	"ProposerSlashing":               func() Object { return &fastssz.ProposerSlashing{} },
	"SignedBLSToExecutionChange":     func() Object { return &fastssz.SignedBLSToExecutionChange{} },
	"SyncAggregate":                  func() Object { return &fastssz.SyncAggregate{} },
	"SyncCommittee":                  func() Object { return &fastssz.SyncCommittee{} },
	"VoluntaryExit":                  func() Object { return &fastssz.VoluntaryExit{} },
	"SignedVoluntaryExit":            func() Object { return &fastssz.SignedVoluntaryExit{} },
	"Validator":                      func() Object { return &fastssz.Validator{} },
	"Withdrawal":                     func() Object { return &fastssz.Withdrawal{} },
	"ExecutionPayloadCapella":        func() Object { return &fastssz.ExecutionPayloadCapella{} },
	"ExecutionPayloadHeaderCapella":  func() Object { return &fastssz.ExecutionPayloadHeaderCapella{} },
	"ExecutionPayloadDeneb":          func() Object { return &fastssz.ExecutionPayloadDeneb{} },
	"ExecutionPayloadHeaderDeneb":    func() Object { return &fastssz.ExecutionPayloadHeaderDeneb{} },
	"BeaconState":                    func() Object { return &fastssz.BeaconState{} },
	"BeaconStateAltair":              func() Object { return &fastssz.BeaconStateAltair{} },
	"BeaconStateBellatrix":           func() Object { return &fastssz.BeaconStateBellatrix{} },
	"BeaconStateCapella":             func() Object { return &fastssz.BeaconStateCapella{} },
	"BeaconStateDeneb":               func() Object { return &fastssz.BeaconStateDeneb{} },
	"BeaconBlockBody":                func() Object { return &fastssz.BeaconBlockBody{} },
	"BeaconBlockBodyAltair":          func() Object { return &fastssz.BeaconBlockBodyAltair{} },
	"BeaconBlockBodyBellatrix":       func() Object { return &fastssz.BeaconBlockBodyBellatrix{} },
	"BeaconBlockBodyCapella":         func() Object { return &fastssz.BeaconBlockBodyCapella{} },
	"BeaconBlockBodyDeneb":           func() Object { return &fastssz.BeaconBlockBodyDeneb{} },
	"BeaconBlock":                    func() Object { return &fastssz.BeaconBlock{} },
	"SingleFieldTestStructMonolith":  func() Object { return &fastssz.SingleFieldTestStructMonolith{} },
	"SmallTestStructMonolith":        func() Object { return &fastssz.SmallTestStructMonolith{} },
	"FixedTestStructMonolith":        func() Object { return &fastssz.FixedTestStructMonolith{} },
	"BitsStructMonolith":             func() Object { return &fastssz.BitsStructMonolith{} },
	"ExecutionPayloadMonolith":       func() Object { return &fastssz.ExecutionPayloadMonolith{} },
	"ExecutionPayloadMonolith2":      func() Object { return &fastssz.ExecutionPayloadMonolith2{} },
	"ExecutionPayloadHeaderMonolith": func() Object { return &fastssz.ExecutionPayloadHeaderMonolith{} },
	"BeaconBlockBodyMonolith":        func() Object { return &fastssz.BeaconBlockBodyMonolith{} },
	"BeaconStateMonolith":            func() Object { return &fastssz.BeaconStateMonolith{} },
	"ValidatorMonolith":              func() Object { return &fastssz.ValidatorMonolith{} },
	"WithdrawalVariation":            func() Object { return &fastssz.WithdrawalVariation{} },
	"HistoricalBatchVariation":       func() Object { return &fastssz.HistoricalBatchVariation{} },
	"ExecutionPayloadVariation":      func() Object { return &fastssz.ExecutionPayloadVariation{} },
	"AttestationVariation1":          func() Object { return &fastssz.AttestationVariation1{} },
	"AttestationVariation2":          func() Object { return &fastssz.AttestationVariation2{} },
	"AttestationVariation3":          func() Object { return &fastssz.AttestationVariation3{} },
	"AttestationDataVariation1":      func() Object { return &fastssz.AttestationDataVariation1{} },
	"AttestationDataVariation2":      func() Object { return &fastssz.AttestationDataVariation2{} },
	"AttestationDataVariation3":      func() Object { return &fastssz.AttestationDataVariation3{} },
}

func createFastsszObjectByName(typeName string) (Object, error) {
	factory, ok := fastsszFactoryMapping[typeName]
	if !ok {
		return nil, fmt.Errorf("unmapped fastssz type: %s", typeName)
	}
	return factory(), nil
}

//------------------------------------------------------------------------------------
// (3) Bridge (karalabe -> fastssz)
//------------------------------------------------------------------------------------

var bridgedCache sync.Map

// BridgeKaralabeToFastssz : karalabe -> fastssz
func BridgeKaralabeToFastssz(k any) (any, error) {
	if k == nil {
		return nil, nil
	}
	rv := reflect.ValueOf(k)
	if rv.Kind() != reflect.Ptr {
		if rv.CanAddr() {
			rv = rv.Addr()
		} else {
			return bridgeValue(rv)
		}
	}
	key := rv.Pointer()
	if cached, ok := bridgedCache.Load(key); ok {
		return cached, nil
	}
	result, err := bridgeValue(rv)
	if err != nil {
		return nil, err
	}
	bridgedCache.Store(key, result)
	return result, nil
}

//------------------------------------------------------------------------------------
// (4) bridgeValue + type-check
//------------------------------------------------------------------------------------

func bridgeValue(v reflect.Value) (any, error) {
	if !v.IsValid() {
		return nil, nil
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return nil, nil
		}
		if isUint256Type(v.Type()) {
			ptr, ok := v.Interface().(*uint256.Int)
			if !ok {
				return nil, fmt.Errorf("bridgeValue: not *uint256.Int")
			}
			return convertUint256ToByte32(ptr), nil
		}
		return bridgeValue(v.Elem())

	case reflect.Struct:
		// check if it's a bare uint256.Int
		if isUint256Type(v.Type()) {
			var x *uint256.Int
			if v.CanAddr() {
				x, _ = v.Addr().Interface().(*uint256.Int)
			} else {
				tmp := v.Interface().(uint256.Int)
				x = &tmp
			}
			return convertUint256ToByte32(x), nil
		}
		return bridgeStructValue(v)

	case reflect.Slice:
		return bridgeSlice(v)
	case reflect.Array:
		return bridgeArray(v)

	case reflect.Bool:
		return v.Bool(), nil

	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Interface(), nil

	default:
		return v.Interface(), nil
	}
}

func isUint256Type(t reflect.Type) bool {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.PkgPath() == "github.com/holiman/uint256" && t.Name() == "Int"
}

func convertUint256ToByte32(x *uint256.Int) [32]byte {
	var out [32]byte
	if x != nil {
		out = x.Bytes32()
	}
	return out
}

// bridgeStructValue : map each field
func bridgeStructValue(v reflect.Value) (any, error) {
	fastObj, err := newFastsszObjectFromKaralabeType(v.Type())
	if err != nil {
		return nil, err
	}
	fastVal := reflect.ValueOf(fastObj).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fName := t.Field(i).Name
		karField := v.Field(i)
		fastField := fastVal.FieldByName(fName)
		if !fastField.IsValid() {
			return nil, fmt.Errorf("no field '%s' in fastssz type %s", fName, t.Name())
		}
		converted, err := bridgeValue(karField)
		if err != nil {
			return nil, fmt.Errorf("bridge error on field '%s': %w", fName, err)
		}
		cv := reflect.ValueOf(converted)
		if !cv.Type().ConvertibleTo(fastField.Type()) {
			return nil, fmt.Errorf("cannot convert field %s from %s to %s",
				fName, cv.Type(), fastField.Type())
		}
		fastField.Set(cv.Convert(fastField.Type()))
	}
	return fastObj, nil
}

func newFastsszObjectFromKaralabeType(rt reflect.Type) (Object, error) {
	if rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}
	factory, ok := fastsszFactoryMapping[rt.Name()]
	if !ok {
		return nil, fmt.Errorf("unmapped type: %s", rt.Name())
	}
	return factory(), nil
}

//------------------------------------------------------------------------------------
// (5) slice/array bridging
//------------------------------------------------------------------------------------

func bridgeSlice(v reflect.Value) (any, error) {
	n := v.Len()
	bvals := make([]reflect.Value, n)
	for i := 0; i < n; i++ {
		val, err := bridgeValue(v.Index(i))
		if err != nil {
			return nil, err
		}
		bvals[i] = reflect.ValueOf(val)
	}
	var elemType reflect.Type
	if n > 0 {
		elemType = bvals[0].Type()
	} else {
		elemType = v.Type().Elem()
	}
	outSliceType := reflect.SliceOf(elemType)
	outSlice := reflect.MakeSlice(outSliceType, 0, n)
	for _, bv := range bvals {
		if !bv.Type().ConvertibleTo(elemType) {
			return nil, fmt.Errorf("slice mismatch: %v -> %v", bv.Type(), elemType)
		}
		outSlice = reflect.Append(outSlice, bv.Convert(elemType))
	}
	return outSlice.Interface(), nil
}

func bridgeArray(v reflect.Value) (any, error) {
	n := v.Len()
	bvals := make([]reflect.Value, n)
	for i := 0; i < n; i++ {
		val, err := bridgeValue(v.Index(i))
		if err != nil {
			return nil, err
		}
		bvals[i] = reflect.ValueOf(val)
	}
	baseElem := v.Type().Elem()
	if n > 0 {
		baseElem = bvals[0].Type()
	}
	arrType := reflect.ArrayOf(n, baseElem)
	outArr := reflect.New(arrType).Elem()
	for i := 0; i < n; i++ {
		if !bvals[i].Type().ConvertibleTo(baseElem) {
			return nil, fmt.Errorf("array[%d] mismatch: %v -> %v", i, bvals[i].Type(), baseElem)
		}
		outArr.Index(i).Set(bvals[i].Convert(baseElem))
	}
	return outArr.Interface(), nil
}

//------------------------------------------------------------------------------------
// (6) differentialCheckFastssz => if bridging matches fastssz decode
//------------------------------------------------------------------------------------

// commonPrefix
func commonPrefix(a, b []byte) []byte {
	var prefix []byte
	for len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		prefix = append(prefix, a[0])
		a, b = a[1:], b[1:]
	}
	return prefix
}

// marshalAsFastssz
func marshalAsFastssz(v any) ([]byte, error) {
	fs, ok := v.(Object)
	if !ok {
		return nil, fmt.Errorf("marshalAsFastssz: not a fastssz object => %T", v)
	}
	return fs.MarshalSSZ()
}

// differentialCheckFastssz : bridging vs direct fastssz
func differentialCheckFastssz(typeName string, tm *traceManager, inSSZ []byte) bool {
	objKar, err := createKaralabeObjectByName(typeName)
	if err != nil {
		return false
	}
	if err := kssz.DecodeFromBytesOnFork(inSSZ, objKar, kssz.ForkFuture); err != nil {
		return false
	}
	tm.recordStep("DiffFuzz-DecodeFromBytesOnFork", 0)

	objFast, err := createFastsszObjectByName(typeName)
	if err != nil {
		return false
	}
	if err := objFast.UnmarshalSSZ(inSSZ); err != nil {
		return false
	}
	tm.recordStep("DiffFuzz-fastssz-UnmarshalSSZ", 0)

	bridged, err := BridgeKaralabeToFastssz(objKar)
	if err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic(fmt.Sprintf("bridge error: %v", err))
	}

	diff := cmp.Diff(bridged, objFast)
	if diff != "" {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic(fmt.Sprintf("Decoded object mismatch (bridged vs fastssz)\nDiff:\n%s", diff))
	}

	b1, err1 := marshalAsFastssz(bridged)
	if err1 != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic(fmt.Sprintf("failed to marshal bridged: %v", err1))
	}
	tm.recordStep("DiffFuzz-encoded-bridged", len(b1))

	b2, err2 := objFast.MarshalSSZ()
	if err2 != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic(fmt.Sprintf("failed to marshal fastssz: %v", err2))
	}
	tm.recordStep("DiffFuzz-encoded-fastssz", len(b2))

	if !bytes.Equal(b1, b2) {
		pfx := commonPrefix(b1, b2)
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic(fmt.Sprintf("[DiffFuzz] SSZ mismatch => bridged vs fastssz\ncommon prefix len=%d\n", len(pfx)))
	}
	return true
}
