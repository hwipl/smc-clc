package messages

// clcSMCDConfirmMsg stores a SMC-D CLC Confirm message
type clcSMCDConfirmMsg struct {
	// accept and confirm message have the same message fields
	clcSMCDAcceptMsg
}
