//go:build server

package assets

import "embed"

var (
	//go:embed fs/revils.asc fs/*.txt fs/*.zip fs/linux/arm64/*
	assetsFs embed.FS
)
