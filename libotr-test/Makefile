LIBOTR_SRC = ./libotr-src
LIBOTR_TARGET = /tmp/libotr2-3.0.0
LIBORT = $(LIBOTR_TARGET)/lib/libotr.a

CFLAGS = -I$(LIBOTR_TARGET)/include/libotr
LDFLAGS =  -L$(LIBOTR_TARGET)/lib
LDLIBS = -lotr

GIT = git -C $(LIBOTR_SRC)

default:
	echo "No default rule"

$(LIBOTR_SRC):
	git clone https://bugs.otr.im/lib/libotr.git $(LIBOTR_SRC)

$(LIBOTR_TARGET): $(LIBOTR_SRC)
	$(GIT) clean -fd
	$(GIT) checkout 63802c9
	cd $(LIBOTR_SRC) && autoreconf -s -i
	cd $(LIBOTR_SRC) && ./configure --with-pic --prefix=$(LIBOTR_TARGET)
	$(MAKE) -C $(LIBOTR_SRC) install

clean: clean-target clean-libotr-src

clean-libotr-src:
	rm -rf $(LIBOTR_SRC)

clean-target:
	rm -rf $(LIBOTR_TARGET)

