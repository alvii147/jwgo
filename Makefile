GO=go
PKG=.

TESTOPTS=-v
ifdef TESTCASE
	TESTOPTS=$(TESTOPTS) -run $(TESTCASE)
endif

BENCHOPTS=-benchmem
BENCHDIR=benchmark/

.PHONY: test
test:
	$(GO) test $(TESTOPTS) $(PKG)

.PHONY: test
bench:
	cd $(BENCHDIR); $(GO) test $(BENCHOPTS) -bench=$(PKG); cd -
