package protobufs

import (
	"embed"
)

var (

	// FS - Embedded FS access to proto files
	//go:embed commonpb/* revilspb/* dnspb/*
	FS embed.FS
)
