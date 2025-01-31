package tunnel_handlers

/*
	Revils Implant Framework
	Copyright (C) 2022  Bishop Fox

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

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/Kevin-kitnick/revils/implant/revils/transports"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"google.golang.org/protobuf/proto"
)

func TunnelCloseHandler(envelope *revilspb.Envelope, connection *transports.Connection) {
	tunnelClose := &revilspb.TunnelData{
		Closed: true,
	}
	proto.Unmarshal(envelope.Data, tunnelClose)
	tunnel := connection.Tunnel(tunnelClose.TunnelID)
	if tunnel != nil {
		// {{if .Config.Debug}}
		log.Printf("[tunnel] Closing tunnel with id %d", tunnel.ID)
		// {{end}}
		connection.RemoveTunnel(tunnel.ID)
		tunnel.Close() // Call tunnel.Close instead of individually closing each Reader/Writer here
		tunnelDataCache.DeleteTun(tunnel.ID)
	} else {
		// {{if .Config.Debug}}
		log.Printf("[tunnel][tunnelCloseHandler] Received close message for unknown tunnel id %d", tunnelClose.TunnelID)
		// {{end}}
	}
}
