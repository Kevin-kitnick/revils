package registry

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
	"strings"

	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/desertbit/grumble"
	"google.golang.org/protobuf/proto"
)

// RegCreateKeyCmd - Create a new Windows registry key
func RegCreateKeyCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		return
	}
	targetOS := getOS(session, beacon)
	if targetOS != "windows" {
		con.PrintErrorf("Registry operations can only target Windows\n")
		return
	}

	hostname := ctx.Flags.String("hostname")
	hive := ctx.Flags.String("hive")
	if err := checkHive(hive); err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	regPath := ctx.Args.String("registry-path")
	if regPath == "" {
		con.PrintErrorf("You must provide a path\n")
		return
	}
	if strings.Contains(regPath, "/") {
		regPath = strings.ReplaceAll(regPath, "/", "\\")
	}
	pathBaseIdx := strings.LastIndex(regPath, `\`)
	if pathBaseIdx < 0 {
		con.PrintErrorf("invalid path: %s", regPath)
		return
	}
	if len(regPath) < pathBaseIdx+1 {
		con.PrintErrorf("invalid path: %s", regPath)
		return
	}
	finalPath := regPath[:pathBaseIdx]
	key := regPath[pathBaseIdx+1:]

	createKey, err := con.Rpc.RegistryCreateKey(context.Background(), &revilspb.RegistryCreateKeyReq{
		Hive:     hive,
		Path:     finalPath,
		Key:      key,
		Hostname: hostname,
		Request:  con.ActiveTarget.Request(ctx),
	})
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	if createKey.Response != nil && createKey.Response.Async {
		con.AddBeaconCallback(createKey.Response.TaskID, func(task *clientpb.BeaconTask) {
			err = proto.Unmarshal(task.Response, createKey)
			if err != nil {
				con.PrintErrorf("Failed to decode response %s\n", err)
				return
			}
			PrintCreateKey(createKey, finalPath, key, con)
		})
		con.PrintAsyncResponse(createKey.Response)
	} else {
		PrintCreateKey(createKey, finalPath, key, con)
	}
}

// PrintCreateKey - Print the results of the create key command
func PrintCreateKey(createKey *revilspb.RegistryCreateKey, regPath string, key string, con *console.RevilsConsoleClient) {
	if createKey.Response != nil && createKey.Response.Err != "" {
		con.PrintErrorf("%s", createKey.Response.Err)
		return
	}
	con.PrintInfof("Key created at %s\\%s", regPath, key)
}

func getOS(session *clientpb.Session, beacon *clientpb.Beacon) string {
	if session != nil {
		return session.OS
	}
	if beacon != nil {
		return beacon.OS
	}
	panic("no session or beacon")
}
