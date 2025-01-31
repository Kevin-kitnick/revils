package rportfwd

/*
	Revils Implant Framework
	Copyright (C) 2019  Bishop Fox

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

	"github.com/Kevin-kitnick/revils/client/command/settings"
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
)

// StartRportFwdListenerCmd - Start listener for reverse port forwarding on implant
func RportFwdListenersCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}

	rportfwdListeners, err := con.Rpc.GetRportFwdListeners(context.Background(), &revilspb.RportFwdListenersReq{
		Request: con.ActiveTarget.Request(ctx),
	})
	if err != nil {
		con.PrintWarnf("%s\n", err)
		return
	}
	PrintRportFwdListeners(rportfwdListeners, ctx.Flags, con)
}

func PrintRportFwdListeners(rportfwdListeners *revilspb.RportFwdListeners, flags grumble.FlagMap, con *console.RevilsConsoleClient) {
	if rportfwdListeners.Response != nil && rportfwdListeners.Response.Err != "" {
		con.PrintErrorf("%s\n", rportfwdListeners.Response.Err)
		return
	}

	if len(rportfwdListeners.Listeners) == 0 {
		con.PrintInfof("No reverse port forwards\n")
		return
	}

	tw := table.NewWriter()
	tw.SetStyle(settings.GetTableStyle(con))
	tw.AppendHeader(table.Row{
		"ID",
		"Remote Address",
		"Bind Address",
	})
	for _, p := range rportfwdListeners.Listeners {
		tw.AppendRow(table.Row{
			p.ID,
			p.ForwardAddress,
			p.BindAddress,
		})
	}
	con.Printf("%s\n", tw.Render())
}
