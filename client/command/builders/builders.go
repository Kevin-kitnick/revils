package builders

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
	"context"
	"fmt"
	"strings"

	"github.com/Kevin-kitnick/revils/client/command/settings"
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
)

// BuildersCmd - List external builders
func BuildersCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	builders, err := con.Rpc.Builders(context.Background(), &commonpb.Empty{})
	if err != nil {
		con.PrintErrorf("%s", err)
		return
	}
	if len(builders.Builders) == 0 {
		con.PrintInfof("No external builders connected to server\n")
	} else {
		PrintBuilders(builders.Builders, con)
	}
}

func PrintBuilders(externalBuilders []*clientpb.Builder, con *console.RevilsConsoleClient) {
	tw := table.NewWriter()
	tw.SetStyle(settings.GetTableStyle(con))
	tw.AppendHeader(table.Row{
		"Name", "Operator", "Templates", "Platform", "Compiler Targets",
	})
	for _, builder := range externalBuilders {

		targets := []string{}
		for _, target := range builder.Targets {
			targets = append(targets, fmt.Sprintf("%s:%s/%s", target.Format, target.GOOS, target.GOARCH))
		}

		row := table.Row{
			builder.Name,
			builder.OperatorName,
			strings.Join(builder.Templates, ", "),
			fmt.Sprintf("%s/%s", builder.GOOS, builder.GOARCH),
			strings.Join(targets, "\n"),
		}
		tw.AppendRow(table.Row(row))
	}
	con.Printf("%s\n", tw.Render())
}
