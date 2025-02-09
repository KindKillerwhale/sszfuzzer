// corpus_generator.go
//go:build ignore
// +build ignore

//go:generate go run corpus_generator.go

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"text/template"
)

var typeList = []string{
	"SingleFieldTestStruct",
	"SmallTestStruct",
	"FixedTestStruct",
	"BitsStruct",
	"Checkpoint",
	"AttestationData",
	"BeaconBlockHeader",
	"BLSToExecutionChange",
	"Attestation",
	"AggregateAndProof",
	"DepositData",
	"DepositMessage",
	"Deposit",
	"Eth1Block",
	"Eth1Data",
	"ExecutionPayload",
	"ExecutionPayloadHeader",
	"Fork",
	"HistoricalBatch",
	"HistoricalSummary",
	"IndexedAttestation",
	"AttesterSlashing",
	"PendingAttestation",
	"SignedBeaconBlockHeader",
	"ProposerSlashing",
	"SignedBLSToExecutionChange",
	"SyncAggregate",
	"SyncCommittee",
	"VoluntaryExit",
	"SignedVoluntaryExit",
	"Validator",
	"Withdrawal",
	"ExecutionPayloadCapella",
	"ExecutionPayloadHeaderCapella",
	"ExecutionPayloadDeneb",
	"ExecutionPayloadHeaderDeneb",
	"BeaconState",
	"BeaconStateAltair",
	"BeaconStateBellatrix",
	"BeaconStateCapella",
	"BeaconStateDeneb",
	"BeaconBlockBody",
	"BeaconBlockBodyAltair",
	"BeaconBlockBodyBellatrix",
	"BeaconBlockBodyCapella",
	"BeaconBlockBodyDeneb",
	"BeaconBlock",
	"SingleFieldTestStructMonolith",
	"SmallTestStructMonolith",
	"FixedTestStructMonolith",
	"BitsStructMonolith",
	"ExecutionPayloadMonolith",
	"ExecutionPayloadMonolith2",
	"ExecutionPayloadHeaderMonolith",
	"BeaconBlockBodyMonolith",
	"BeaconStateMonolith",
	"ValidatorMonolith",
	"WithdrawalVariation",
	"HistoricalBatchVariation",
	"ExecutionPayloadVariation",
	"AttestationVariation1",
	"AttestationVariation2",
	"AttestationVariation3",
	"AttestationDataVariation1",
	"AttestationDataVariation2",
	"AttestationDataVariation3",
}

const tmplText = `
package main

import (
	types "github.com/KindKillerwhale/sszfuzzer/types/sszgen"
)

{{ range . }}
func GenerateSeedCorpus{{ . }}(outZip string) error {
	// T = *types.{{ . }}, U = types.{{ . }}
	// kind = "{{ . }}"
	return generateSeedCorpus[*types.{{ . }}, types.{{ . }}]("{{ . }}", outZip)
}
{{ end }}
`

type TemplateData struct {
	Types []string
}

func main() {
	data := TemplateData{Types: typeList}

	tmpl, err := template.New("corpus").Parse(tmplText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse template: %v\n", err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data.Types); err != nil {
		fmt.Fprintf(os.Stderr, "failed to execute template: %v\n", err)
		os.Exit(1)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to format generated code: %v\n", err)
		os.Exit(1)
	}

	outFile := "corpus_generated.go"
	if err := os.WriteFile(outFile, formatted, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write generated file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated file %s successfully\n", outFile)
}
