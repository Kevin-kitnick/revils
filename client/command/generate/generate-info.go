package generate

import (
	"context"

	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/desertbit/grumble"
)

// GenerateInfoCmd - Display information about the Revils server's compiler configuration
func GenerateInfoCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	compiler, err := con.Rpc.GetCompiler(context.Background(), &commonpb.Empty{})
	if err != nil {
		con.PrintErrorf("Failed to get compiler information: %s\n", err)
		return
	}
	con.Printf("%sServer:%s %s/%s\n", console.Bold, console.Normal, compiler.GOOS, compiler.GOARCH)
	con.Println()
	con.Printf("%sCross Compilers%s\n", console.Bold, console.Normal)
	for _, cc := range compiler.CrossCompilers {
		con.Printf("%s/%s - %s\n", cc.TargetGOOS, cc.TargetGOARCH, cc.GetCCPath())
	}
	con.Println()
	con.Printf("%sSupported Targets%s\n", console.Bold, console.Normal)
	for _, target := range compiler.Targets {
		con.Printf("%s/%s - %s\n", target.GOOS, target.GOARCH, nameOfOutputFormat(target.Format))
	}
	con.Println()
	con.Printf("%sDefault Builds Only%s\n", console.Bold, console.Normal)
	for _, target := range compiler.UnsupportedTargets {
		con.Printf("%s/%s - %s\n", target.GOOS, target.GOARCH, nameOfOutputFormat(target.Format))
	}
}
