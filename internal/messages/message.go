package messages

// Message is a type for all clc messages
type Message interface {
	Parse([]byte)
	String() string
	Reserved() string
	Dump() string
}
