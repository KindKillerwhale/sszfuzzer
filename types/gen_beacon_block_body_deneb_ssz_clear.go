// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

// ClearSSZ zeroes out all fields of BeaconBlockBodyDeneb for leftover decode.
func (obj *BeaconBlockBodyDeneb) ClearSSZ() {
	obj.RandaoReveal = [96]byte{}
	if obj.Eth1Data != nil {
		obj.Eth1Data.ClearSSZ()
	}
	obj.Graffiti = [32]byte{}
	for i := range obj.ProposerSlashings {
		if obj.ProposerSlashings[i] != nil {
			obj.ProposerSlashings[i].ClearSSZ()
		}
	}
	for i := range obj.AttesterSlashings {
		if obj.AttesterSlashings[i] != nil {
			obj.AttesterSlashings[i].ClearSSZ()
		}
	}
	for i := range obj.Attestations {
		if obj.Attestations[i] != nil {
			obj.Attestations[i].ClearSSZ()
		}
	}
	for i := range obj.Deposits {
		if obj.Deposits[i] != nil {
			obj.Deposits[i].ClearSSZ()
		}
	}
	for i := range obj.VoluntaryExits {
		if obj.VoluntaryExits[i] != nil {
			obj.VoluntaryExits[i].ClearSSZ()
		}
	}
	if obj.SyncAggregate != nil {
		obj.SyncAggregate.ClearSSZ()
	}
	if obj.ExecutionPayload != nil {
		obj.ExecutionPayload.ClearSSZ()
	}
	for i := range obj.BlsToExecutionChanges {
		if obj.BlsToExecutionChanges[i] != nil {
			obj.BlsToExecutionChanges[i].ClearSSZ()
		}
	}
	obj.BlobKzgCommitments = nil
}
