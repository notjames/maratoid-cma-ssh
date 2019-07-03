// Package crd provides the crd assets to a virtual filesystem.
package crd

import (
	_ "github.com/shurcooL/vfsgen"
)

//go:generate go run -tags=dev asset_generate.go
