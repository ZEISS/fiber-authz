.DEFAULT_GOAL := build

# Go variables
GO 						?= go
GO_RELEASER 	?= $(GO_TOOL) github.com/goreleaser/goreleaser/v2
GO_LINT 			?= $(GO_TOOL) github.com/golangci/golangci-lint/v2/cmd/golangci-lint
GO_TOOL 			?= $(GO) tool
GO_TEST 			?= $(GO_TOOL) gotest.tools/gotestsum --format pkgname

.PHONY: build
build: ## Build the binary file.
	$(GO_RELEASER) build --snapshot --clean

.PHONY: release
release: ## Release the project.
	$(GO_RELEASER) release --clean

.PHONY: generate
generate: ## Generate code.
	$(GO) generate ./...

.PHONY: mocks
mocks: ## Generate mocks.
	$(GO_TOOL) github.com/vektra/mockery/v2

.PHONY: dex
dex: ## Generate mocks.
	$(GO_TOOL) github.com/dexidp/dex/cmd/dex serve dex-dev.yml

.PHONY: fmt
fmt: ## Run go fmt against code.
	$(GO_TOOL) mvdan.cc/gofumpt -w .

.PHONY: vet
vet: ## Run go vet against code.
	$(GO) vet ./...

.PHONY: test
test: fmt vet ## Run tests.
	mkdir -p .test/reports
	$(GO_TEST) --junitfile .test/reports/unit-test.xml -- -race ./... -count=1 -short -cover -coverprofile .test/reports/unit-test-coverage.out

.PHONY: lint
lint: ## Run lint.
	$(GO_LINT) run --timeout 5m -c .golangci.yml

.PHONY: fix
fix: ## Run lint auto-fixes.
	$(GO_LINT) run --fix --timeout 5m -c .golangci.yml

.PHONY: clean
clean: ## Remove previous build.
	@rm -rf .test .dist
	@find . -type f -name '*.gen.go' -exec rm {} +
	@$(GO_LINT) cache clean
	@$(GO) clean -modcache
	@git checkout go.mod

.PHONY: help
help: ## Display this help screen.
	@grep -E '^[a-z.A-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
