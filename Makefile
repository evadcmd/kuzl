# make build                          bin/kuzl with policy.yaml built in
# make build POLICY=/path/policy.yaml  with that policy instead
#
# The policy is built in, not read at run time, so that an agent running
# kuzl can't change it. See policy.yaml. POLICY can't be empty: a binary
# without a policy allows no host, which is of no use.

POLICY ?= policy.yaml

ifeq ($(POLICY),)
$(error POLICY is empty: a binary without a policy allows no host)
endif
ifeq ($(wildcard $(POLICY)),)
$(error POLICY=$(POLICY) does not exist)
endif
# -X sets a string; base64 keeps the YAML's newlines and quotes out of it.
LDFLAGS := -X github.com/evadcmd/kuzl/internal/config.builtin=$(shell base64 < '$(POLICY)' | tr -d '\n')

.PHONY: build
build:
	go build -ldflags '$(LDFLAGS)' -o bin/kuzl ./cmd/kuzl
	@# Validates the policy: a build that took in a bad one doesn't stay.
	bin/kuzl policy || { rm -f bin/kuzl; exit 1; }
