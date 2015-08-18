TEST_HELPER = /tmp/a.out

LIBOTR_TARGET = /tmp/libotr2-3.0.0
CFLAGS = -I$(LIBOTR_TARGET)/include/libotr
LDFLAGS =  -L$(LIBOTR_TARGET)/lib
LDLIBS = -lotr

default: libotr-compat

libotr-compat: $(TEST_HELPER)
	go test -v -tags="LIBOTR2-v3.0.0" -ldflags "-X github.com/twstrike/otr3/compat.numIterations 1000"

$(TEST_HELPER): $(LIBOTR_TARGET) libotr_test_helper.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LDLIBS) -o $(TEST_HELPER) libotr_test_helper.c

$(LIBOTR_TARGET):
	$(MAKE) -C ../libotr-test $(LIBOTR_TARGET)

clean: clean-target
	$(RM) $(TEST_HELPER)

clean-target:
	rm -rf $(LIBOTR_TARGET)

