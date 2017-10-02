// +build linux darwin
// +build libotr2

package compat

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/coyim/otr3"
)

var (
	numIterations   = "0"
	disabledMessage = `You must set "github.com/coyim/otr3/compat.numIterations".
	For instance, if you want to run 5 iterations, use:
	  go test -ldflags "-X github.com/coyim/otr3/compat.numIterations 5"
`
)

var alicePrivateKeyHex = "000000000080c81c2cb2eb729b7e6fd48e975a932c638b3a9055478583afa46755683e30102447f6da2d8bec9f386bbb5da6403b0040fee8650b6ab2d7f32c55ab017ae9b6aec8c324ab5844784e9a80e194830d548fb7f09a0410df2c4d5c8bc2b3e9ad484e65412be689cf0834694e0839fb2954021521ffdffb8f5c32c14dbf2020b3ce7500000014da4591d58def96de61aea7b04a8405fe1609308d000000808ddd5cb0b9d66956e3dea5a915d9aba9d8a6e7053b74dadb2fc52f9fe4e5bcc487d2305485ed95fed026ad93f06ebb8c9e8baf693b7887132c7ffdd3b0f72f4002ff4ed56583ca7c54458f8c068ca3e8a4dfa309d1dd5d34e2a4b68e6f4338835e5e0fb4317c9e4c7e4806dafda3ef459cd563775a586dd91b1319f72621bf3f00000080b8147e74d8c45e6318c37731b8b33b984a795b3653c2cd1d65cc99efe097cb7eb2fa49569bab5aab6e8a1c261a27d0f7840a5e80b317e6683042b59b6dceca2879c6ffc877a465be690c15e4a42f9a7588e79b10faac11b1ce3741fcef7aba8ce05327a2c16d279ee1b3d77eb783fb10e3356caa25635331e26dd42b8396c4d00000001420bec691fea37ecea58a5c717142f0b804452f57"

type securityEventHandler struct {
	newKeys bool
}

func (h *securityEventHandler) HandleSecurityEvent(event otr3.SecurityEvent) {
	switch event {
	case otr3.GoneSecure, otr3.StillSecure:
		h.newKeys = true
	}
}

// This test requires libotr_test_helper.c to be built as /tmp/a.out.
func TestAgainstLibOTR(t *testing.T) {
	limit, err := strconv.Atoi(numIterations)
	if limit == 0 || err != nil {
		t.Skip(disabledMessage)
	}

	alicePrivateKey, _ := hex.DecodeString(alicePrivateKeyHex)
	alice := &otr3.Conversation{}
	alice.Policies.AllowV2()

	_, _, k := otr3.ParsePrivateKey(alicePrivateKey)
	alice.SetOurKeys([]otr3.PrivateKey{k})

	cmd := exec.Command("/tmp/a.out")
	cmd.Stderr = os.Stderr

	out, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()

	in := bufio.NewReader(stdout)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	out.Write([]byte("?OTRv23?"))
	out.Write([]byte("\n"))
	var expectedText = []byte("test message")

	h := &securityEventHandler{}
	alice.SetSecurityEventHandler(h)

	for i := 0; i < limit; i++ {
		line, isPrefix, err := in.ReadLine()
		if isPrefix {
			t.Fatal("line from subprocess too long")
		}
		if err != nil {
			t.Fatal(err)
		}

		text, alicesMessage, err := alice.Receive(line)
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range alicesMessage {
			out.Write(msg)
			out.Write([]byte("\n"))
		}

		if h.newKeys {
			h.newKeys = false

			alicesMessage, err := alice.Send([]byte("Go -> libotr test message"))
			if err != nil {
				t.Errorf("error sending message: %s", err.Error())
			} else {
				for _, msg := range alicesMessage {
					out.Write(msg)
					out.Write([]byte("\n"))
				}
			}
		}

		if len(text) > 0 {
			if !bytes.Equal(text, expectedText) {
				t.Errorf("expected %x, but got %x", expectedText, text)
			}
			if !alice.IsEncrypted() {
				t.Error("message wasn't encrypted")
			}
		}
	}
}
