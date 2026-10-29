# make build                          bin/kuzl with policy.yaml built in
# make build POLICY=/path/policy.yaml  with that policy instead
# make build POLICY=                   without a policy: every public host
#
# The policy is built in, not read at run time, so that an agent running
# kuzl can't change it. See policy.yaml.

POLICY ?= policy.yaml
LDFLAGS :=

ifneq ($(POLICY),)
ifeq ($(wildcard $(POLICY)),)
$(error POLICY=$(POLICY) does not exist)
endif
# -X sets a string; base64 keeps the YAML's newlines and quotes out of it.
LDFLAGS += -X github.com/evadcmd/kuzl/internal/config.builtin=$(shell base64 < '$(POLICY)' | tr -d '\n')
endif

.PHONY: build
build:
	go build -ldflags '$(LDFLAGS)' -o bin/kuzl ./cmd/kuzl
	@# Validates the policy: a build that took in a bad one doesn't stay.
	bin/kuzl policy || { rm -f bin/kuzl; exit 1; }
