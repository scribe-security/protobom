# ANSI color escape codes
BOLD :=  \033[1m
CYAN :=  \033[36m
GREEN := \033[32m
RESET := \033[0m

.PHONY: help
help:
	@grep -Eh '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: conformance
conformance: ## Regenerate the conformance golden samples. Only to be run when changes are expected
	go run ./test/conformance/generator/ test/conformance/testdata/

.PHONY: conformance-test
conformance-test: ## Run the conformance test suite
	go test ./test/conformance/...

.PHONY: proto
proto: ## Rebuild protobuf autogenerated code
	protoc --go_out=pkg api/sbom.proto

.PHONY: fakes
fakes: ## Rebuild the fake implementations
	go generate ./...
