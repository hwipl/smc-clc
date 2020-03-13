package cmd

import (
	"bytes"
	"testing"
)

func TestBuffer(t *testing.T) {
	var buf buffer
	var want []byte
	var got []byte

	got = buf.copyBuffer().Bytes()
	if !bytes.Equal(want, got) {
		t.Errorf("buf = %s; want %s", got, want)
	}

	want = []byte("hello world")
	buf.Write(want)
	got = buf.copyBuffer().Bytes()
	if !bytes.Equal(want, got) {
		t.Errorf("buf = %s; want %s", got, want)
	}

	buf.Write(want)
	want = []byte("hello worldhello world")
	got = buf.copyBuffer().Bytes()
	if !bytes.Equal(want, got) {
		t.Errorf("buf = %s; want %s", got, want)
	}

	buf.reset()
	want = []byte("")
	got = buf.copyBuffer().Bytes()
	if !bytes.Equal(want, got) {
		t.Errorf("buf = %s; want %s", got, want)
	}
}
