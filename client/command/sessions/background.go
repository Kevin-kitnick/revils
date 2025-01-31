package sessions

import (
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/desertbit/grumble"
)

// BackgroundCmd - Background the active session
func BackgroundCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	con.ActiveTarget.Background()
	con.PrintInfof("Background ...\n")
}
