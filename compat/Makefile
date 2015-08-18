TEST_HELPER = /tmp/a.out

LIBOTR_TARGET = /tmp/libotr2-3.0.0
CFLAGS = -I$(LIBOTR_TARGET)/include/libotr
LDFLAGS =  -L$(LIBOTR_TARGET)/lib
LDLIBS = -lotr

default: libotr-compat

libotr-compat: $(TEST_HELPER)
	LD_LIBRARY_PATH=$(LIBOTR_TARGET)/lib \
	go test -v \
	-run=TestAgainstLibOTR \
	-tags="libotr2" \
	-ldflags "-X github.com/twstrike/otr3/compat.numIterations 1000"

$(TEST_HELPER): $(LIBOTR_TARGET) libotr_test_helper.c
	$(CC) libotr_test_helper.c $(LDLIBS) $(LDFLAGS) $(CFLAGS) -o $(TEST_HELPER)

$(LIBOTR_TARGET):
	$(MAKE) -C ../libotr-test $(LIBOTR_TARGET)

clean: clean-target
	$(RM) $(TEST_HELPER)

clean-target:
	rm -rf $(LIBOTR_TARGET)

