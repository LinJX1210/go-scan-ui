// Package web 内嵌前端静态文件，编译后为单个可执行文件。
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// Static 返回前端静态文件系统。
func Static() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
