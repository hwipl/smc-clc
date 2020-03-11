package clc

// clcSMCRConfirmMsg stores a CLC Confirm message
type clcSMCRConfirmMsg struct {
	// accept and confirm messages have the same message fields
	clcSMCRAcceptMsg
}
