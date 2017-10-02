GO_VERSION=$(shell go version | grep  -o 'go[[:digit:]]\.[[:digit:]]')

TEST_HELPER = /tmp/a.out

LIBOTR_TARGET = /tmp/libotr2-3.0.0
CFLAGS = -I$(LIBOTR_TARGET)/include/libotr
LDFLAGS =  -L$(LIBOTR_TARGET)/lib
LDLIBS = -lotr

empty:=
space:= $(empty) $(empty)

ifeq ($(GO_VERSION), go1.4)
	SEPARATION_CHAR=$(space)
else
	SEPARATION_CHAR==
endif

default: libotr-compat

libotr-compat: $(TEST_HELPER)
	LD_LIBRARY_PATH=$(LIBOTR_TARGET)/lib \
	go test -v \
	-run=TestAgainstLibOTR \
	-tags="libotr2" \
	-ldflags "-X github.com/coyim/otr3/compat.numIterations$(SEPARATION_CHAR)1000 -X github.com/coyim/otr3.dontIgnoreFastRepeatQueryMessage$(SEPARATION_CHAR)true"

$(TEST_HELPER): $(LIBOTR_TARGET) libotr_test_helper.c
	$(CC) libotr_test_helper.c $(LDLIBS) $(LDFLAGS) $(CFLAGS) -o $(TEST_HELPER)

$(LIBOTR_TARGET):
	$(MAKE) -C ../libotr-test $(LIBOTR_TARGET)

clean: clean-target
	$(RM) $(TEST_HELPER)

clean-target:
	rm -rf $(LIBOTR_TARGET)
