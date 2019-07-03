// +build dev

package crd

import (
	"go/build"
	"log"
	"net/http"

	"github.com/samsung-cnct/cma-ssh/pkg/util"
)

func importPathToDir(importPath string) string {
	p, err := build.Import(importPath, "", build.FindOnly)
	if err != nil {
		log.Fatalln(err)
	}
	return p.Dir
}

var Crd = util.ZeroModTimeFileSystem{Source: http.Dir(
	importPathToDir("github.com/samsung-cnct/cma-ssh/crd"),
)}
