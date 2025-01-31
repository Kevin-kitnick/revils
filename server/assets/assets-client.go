//go:build client

package assets

import "embed"

var (
	//go:embed fs/english.txt fs/revils.asc
	assetsFs embed.FS
)
