package messages

// trailer stores a CLC message trailer
type trailer eyecatcher

// String converts the message trailer to a string
func (t trailer) String() string {
	return eyecatcher(t).String()
}
