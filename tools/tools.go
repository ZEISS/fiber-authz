//go:build tools
// +build tools

package tools

import (
	_ "github.com/golang/mock/mockgen/model"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/goreleaser/goreleaser"
	_ "gotest.tools/gotestsum"
	_ "mvdan.cc/gofumpt"
)
