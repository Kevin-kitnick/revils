package wireguard

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
	"net"

	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/desertbit/grumble"
)

// WGPortFwdAddCmd - Add a new WireGuard port forward
func WGPortFwdAddCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	if session.Transport != "wg" {
		con.PrintErrorf("This command is only supported for WireGuard implants")
		return
	}

	localPort := ctx.Flags.Int("bind")
	remoteAddr := ctx.Flags.String("remote")
	if remoteAddr == "" {
		con.PrintErrorf("Must specify a remote target host:port")
		return
	}
	remoteHost, remotePort, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		con.PrintErrorf("Failed to parse remote target %s\n", err)
		return
	}

	portfwdAdd, err := con.Rpc.WGStartPortForward(context.Background(), &revilspb.WGPortForwardStartReq{
		LocalPort:     int32(localPort),
		RemoteAddress: remoteAddr,
		Request:       con.ActiveTarget.Request(ctx),
	})

	if err != nil {
		con.PrintErrorf("Error: %v", err)
		return
	}

	if portfwdAdd.Response != nil && portfwdAdd.Response.Err != "" {
		con.PrintErrorf("Error: %s\n", portfwdAdd.Response.Err)
		return
	}
	con.PrintInfof("Port forwarding %s -> %s:%s\n", portfwdAdd.Forwarder.LocalAddr, remoteHost, remotePort)
}
