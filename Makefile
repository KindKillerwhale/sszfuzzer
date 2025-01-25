# cp -r karalabe/ssz/tests/testtypes/consensus-spec-tests sszfuzzer/types
CONSENSUS_DIR := types/consensus-spec-tests
CLEAR_DIR     := types/clearSSZ
MERGED_DIR    := types/sszgen

CLEAR_SOURCES := $(wildcard $(CLEAR_DIR)/gen_*_ssz.go)
CONSENSUS_SOURCES := $(patsubst $(CLEAR_DIR)/%,$(CONSENSUS_DIR)/%,$(CLEAR_SOURCES))
MERGED_SOURCES := $(patsubst $(CLEAR_DIR)/%,$(MERGED_DIR)/%,$(CLEAR_SOURCES))

all: merge

merge: $(MERGED_SOURCES)
	@echo "All merged outputs are in $(MERGED_DIR)"

$(MERGED_DIR)/%: $(CLEAR_DIR)/% $(CONSENSUS_DIR)/%
	@mkdir -p $(MERGED_DIR)
	@echo "[MERGE] $^ -> $@"
	echo "// Code generated by merging. DO NOT EDIT." > $@
	echo "package sszgen" >> $@
	echo "" >> $@ 

	grep -v '^package ' $(word 2,$^) \
	| grep -v '^// Code generated' \
	>> $@

	grep -v '^package ' $(word 1,$^) \
	| grep -v '^// Code generated' \
	>> $@

	goimports -w $@

clean:
	rm -f $(MERGED_DIR)/gen_*_ssz.go

.PHONY: all merge clean
