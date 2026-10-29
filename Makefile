# make build                          bin/kuzl without a policy: every public host
# make build POLICY=/path/policy.yaml  bin/kuzl with that policy built in
#
# The policy lives outside the repo (policy.yaml here is gitignored), so that
# changing it takes a rebuild, not a commit. See policy.example.yaml.

POLICY ?=
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
