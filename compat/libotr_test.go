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
)

var (
	numIterations   = "0"
	disabledMessage = `You must set "github.com/twstrike/otr3/compat.numIterations".
	For instance, if you want to run 5 iterations, use:
	  go test -ldflags "-X github.com/twstrike/otr3/compat.numIterations 5"
`
)

// This test requires libotr_test_helper.c to be built as /tmp/a.out.
func TestAgainstLibOTR(t *testing.T) {
	limit, err := strconv.Atoi(numIterations)
	if limit == 0 || err != nil {
		t.Skip(disabledMessage)
	}

	alicePrivateKey, _ := hex.DecodeString(alicePrivateKeyHex)
	var alice Conversation
	alice.PrivateKey = new(PrivateKey)
	alice.PrivateKey.Parse(alicePrivateKey)

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

	out.Write([]byte(QueryMessage))
	out.Write([]byte("\n"))
	var expectedText = []byte("test message")

	for i := 0; i < limit; i++ {
		line, isPrefix, err := in.ReadLine()
		if isPrefix {
			t.Fatal("line from subprocess too long")
		}
		if err != nil {
			t.Fatal(err)
		}
		text, encrypted, change, alicesMessage, err := alice.Receive(line)
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range alicesMessage {
			out.Write(msg)
			out.Write([]byte("\n"))
		}
		if change == NewKeys {
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
			if !encrypted {
				t.Error("message wasn't encrypted")
			}
		}
	}
}
