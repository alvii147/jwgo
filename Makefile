GO=go
PKG=.

TESTOPTS=-v
ifdef TESTCASE
	TESTOPTS=$(TESTOPTS) -run $(TESTCASE)
endif

BENCHOPTS=-benchmem

.PHONY: test
test:
	$(GO) test $(TESTOPTS) $(PKG)

.PHONY: test
bench:
	$(GO) test $(BENCHOPTS) -bench=$(PKG)
