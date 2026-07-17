package server

import "embed"

//go:embed static/*.html
var assets embed.FS
