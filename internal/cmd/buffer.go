package cmd

import (
	"bytes"
	"sync"
)

// buffer is a bytes.Buffer protected by a mutex
type buffer struct {
	lock   sync.Mutex
	buffer bytes.Buffer
}

// Write writes p to the buffer
func (b *buffer) Write(p []byte) (n int, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.buffer.Write(p)
}

// copyBuffer copies the underlying bytes.Buffer and returns it
func (b *buffer) copyBuffer() *bytes.Buffer {
	b.lock.Lock()
	defer b.lock.Unlock()
	oldBuf := b.buffer.Bytes()
	newBuf := make([]byte, len(oldBuf))
	copy(newBuf, oldBuf)
	return bytes.NewBuffer(newBuf)
}
