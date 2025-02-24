package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	kssz "github.com/karalabe/ssz"
)

// traceStep / traceScenario struct (fuzzer style)
type traceStep struct {
	Method   string `json:"method"`
	Leftover int    `json:"leftover"`
}

type traceScenario struct {
	InputHex string      `json:"input_hex"`
	Steps    []traceStep `json:"steps"`
}

// traceManager logs steps
type traceManager struct {
	mu    sync.Mutex
	steps []traceStep
}

func NewTraceManager() *traceManager {
	return &traceManager{}
}

func (tm *traceManager) recordStep(method string, leftover int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.steps = append(tm.steps, traceStep{
		Method:   method,
		Leftover: leftover,
	})
}

func (tm *traceManager) buildScenario(input []byte) traceScenario {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	cp := make([]traceStep, len(tm.steps))
	copy(cp, tm.steps)
	return traceScenario{
		InputHex: hex.EncodeToString(input),
		Steps:    cp,
	}
}

// dumpTraceScenario writes crash_<timestamp>.json
func dumpTraceScenario(s traceScenario) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal scenario: %v\n", err)
		return
	}
	filename := fmt.Sprintf("crash_%d.json", time.Now().UnixNano())
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write scenario: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Crash scenario dumped to %s\n", filename)
	}
}

// ReproduceCrash reads crash_xxx.json and runs the same steps as fuzzer.
func ReproduceCrash(typeName, scenarioPath, outLogPath string) error {
	scenarioData, err := os.ReadFile(scenarioPath)
	if err != nil {
		return fmt.Errorf("read scenario file: %w", err)
	}
	var sc struct {
		InputHex string `json:"input_hex"`
		Steps    []struct {
			Method   string `json:"method"`
			Leftover int    `json:"leftover"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(scenarioData, &sc); err != nil {
		return fmt.Errorf("unmarshal scenario: %w", err)
	}

	inSSZ, err := hex.DecodeString(sc.InputHex)
	if err != nil {
		return fmt.Errorf("decode input_hex: %w", err)
	}

	tm := NewTraceManager()
	tm.recordStep("StartFuzz", len(inSSZ))

	// panic handler
	defer func() {
		if r := recover(); r != nil {
			scn := tm.buildScenario(inSSZ)
			dumpTraceScenario(scn)
			saveReproduceLog(outLogPath, scn, fmt.Sprintf("PANIC: %v", r))
			panic(r)
		} else {
			scn := tm.buildScenario(inSSZ)
			saveReproduceLog(outLogPath, scn, "OK (no panic)")
		}
	}()

	doFuzzerLogic(typeName, inSSZ, tm)
	return nil
}

// doFuzzerLogic mirrors fuzzConsensusSpecType from fuzzer.
func doFuzzerLogic(typeName string, inSSZ []byte, tm *traceManager) {
	var valid bool

	// (a) stream-based decode/encode
	if objKar, err := createKaralabeObjectByName(typeName); err == nil {
		if decodeStreamRoundtrip(objKar, tm, inSSZ) {
			finalChecks(objKar, inSSZ)
			if differentialCheckFastssz(typeName, tm, inSSZ) {
				valid = true
			}
		}
	}

	// (b) buffer-based decode/encode
	if !valid {
		if objKar2, err := createKaralabeObjectByName(typeName); err == nil {
			if decodeBufferRoundtrip(objKar2, tm, inSSZ) {
				finalChecks(objKar2, inSSZ)
				if differentialCheckFastssz(typeName, tm, inSSZ) {
					valid = true
				}
			}
		}
	}

	// (c) if valid => handleValidCase
	if valid {
		handleValidCase(typeName, tm, inSSZ)
	}
}

// decodeStreamRoundtrip
func decodeStreamRoundtrip(obj kssz.Object, tm *traceManager, inSSZ []byte) bool {
	r := bytes.NewReader(inSSZ)
	err := kssz.DecodeFromStreamOnFork(r, obj, uint32(len(inSSZ)), kssz.ForkFuture)
	tm.recordStep("DecodeFromStreamOnFork", r.Len())

	if err != nil {
		return false
	}
	var buf bytes.Buffer
	if err := kssz.EncodeToStreamOnFork(&buf, obj, kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic(fmt.Sprintf("failed to re-encode stream: %v", err))
	}
	tm.recordStep("EncodeToStreamOnFork", buf.Len())

	if !bytes.Equal(buf.Bytes(), inSSZ) {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("re-encoded stream mismatch")
	}
	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("failed to decode buffer again")
	}
	return true
}

// decodeBufferRoundtrip
func decodeBufferRoundtrip(obj kssz.Object, tm *traceManager, inSSZ []byte) bool {
	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj, kssz.ForkFuture); err != nil {
		return false
	}
	tm.recordStep("DecodeFromBytesOnFork", 0)

	sz := kssz.SizeOnFork(obj, kssz.ForkFuture)
	bin := make([]byte, sz)
	if err := kssz.EncodeToBytesOnFork(bin, obj, kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("failed to re-encode buffer")
	}
	tm.recordStep("EncodeToBytesOnFork", len(bin))

	if !bytes.Equal(bin, inSSZ) {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("re-encoded buffer mismatch")
	}
	r := bytes.NewReader(inSSZ)
	if err := kssz.DecodeFromStreamOnFork(r, obj, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("failed to decode stream (buffer-based roundtrip)")
	}
	tm.recordStep("DecodeFromStreamOnFork", r.Len())

	return true
}

// finalChecks
func finalChecks(obj kssz.Object, inSSZ []byte) {
	hSeq := kssz.HashSequentialOnFork(obj, kssz.ForkFuture)
	hConc := kssz.HashConcurrentOnFork(obj, kssz.ForkFuture)
	if hSeq != hConc {
		panic("hash mismatch (sequential vs concurrent)")
	}
	sz := kssz.SizeOnFork(obj, kssz.ForkFuture)
	if sz != uint32(len(inSSZ)) {
		panic("size mismatch in finalChecks")
	}
}

// handleValidCase
func handleValidCase(typeName string, tm *traceManager, inSSZ []byte) {
	obj1, err := createKaralabeObjectByName(typeName)
	if err != nil {
		return
	}
	if c, ok := obj1.(interface{ ClearSSZ() }); ok {
		c.ClearSSZ()
	}
	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj1, kssz.ForkFuture); err != nil {
		panic("handleValidCase decodeFromBytesOnFork failed")
	}
	tm.recordStep("handleValidCase-DecodeFromBytesOnFork", 0)

	r := bytes.NewReader(inSSZ)
	if err := kssz.DecodeFromStreamOnFork(r, obj1, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("handleValidCase stream decode failed")
	}
	tm.recordStep("handleValidCase-DecodeFromStreamOnFork", r.Len())

	var buf bytes.Buffer
	if err := kssz.EncodeToStreamOnFork(&buf, obj1, kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("handleValidCase stream encode failed")
	}
	tm.recordStep("handleValidCase-EncodeToStreamOnFork", buf.Len())

	if !bytes.Equal(buf.Bytes(), inSSZ) {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("handleValidCase mismatch (stream-based)")
	}
	finalChecks(obj1, inSSZ)

	obj2, err := createKaralabeObjectByName(typeName)
	if err != nil {
		return
	}
	if c, ok := obj2.(interface{ ClearSSZ() }); ok {
		c.ClearSSZ()
	}
	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj2, kssz.ForkFuture); err != nil {
		panic("handleValidCase decodeFromBytesOnFork #2 failed")
	}
	tm.recordStep("handleValidCase-DecodeFromBytesOnFork", 0)

	if err := kssz.DecodeFromBytesOnFork(inSSZ, obj2, kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("handleValidCase second decode failed")
	}
	tm.recordStep("handleValidCase-DecodeFromBytesOnFork", 0)

	bin := make([]byte, kssz.SizeOnFork(obj2, kssz.ForkFuture))
	if err := kssz.EncodeToBytesOnFork(bin, obj2, kssz.ForkFuture); err != nil {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("handleValidCase buffer encode failed")
	}
	tm.recordStep("handleValidCase-EncodeToBytesOnFork", len(bin))

	if !bytes.Equal(bin, inSSZ) {
		sc := tm.buildScenario(inSSZ)
		dumpTraceScenario(sc)
		panic("handleValidCase mismatch (buffer-based)")
	}
	finalChecks(obj2, inSSZ)
	crossForkCheck(tm, inSSZ, obj2)
}

// crossForkCheck tries all known forks.
func crossForkCheck(tm *traceManager, inSSZ []byte, obj kssz.Object) {
	for forkName, forkVal := range kssz.ForkMapping {
		if forkVal == kssz.ForkUnknown {
			continue
		}
		if c, ok := obj.(interface{ ClearSSZ() }); ok {
			c.ClearSSZ()
		}
		r := bytes.NewReader(inSSZ)
		err := kssz.DecodeFromStreamOnFork(r, obj, uint32(len(inSSZ)), forkVal)
		tm.recordStep(fmt.Sprintf("crossFork-decode-%s", forkName), r.Len())

		if err == nil {
			sz2 := kssz.SizeOnFork(obj, forkVal)
			out2 := make([]byte, sz2)
			if err2 := kssz.EncodeToBytesOnFork(out2, obj, forkVal); err2 == nil {
				tm.recordStep(fmt.Sprintf("crossFork-encode-%s", forkName), len(out2))
			} else {
				sc := tm.buildScenario(inSSZ)
				dumpTraceScenario(sc)
				panic(fmt.Sprintf("[crossFork] fork=%s => encode fail: %v", forkName, err2))
			}
		}
	}
}

// saveReproduceLog
func saveReproduceLog(outLogPath string, scenario traceScenario, final string) {
	data := struct {
		InputHex    string      `json:"input_hex"`
		Steps       []traceStep `json:"steps"`
		FinalResult string      `json:"final_result"`
	}{
		InputHex:    scenario.InputHex,
		Steps:       scenario.Steps,
		FinalResult: final,
	}
	b, _ := json.MarshalIndent(data, "", "  ")
	_ = os.WriteFile(outLogPath, b, 0644)
}
