package pivots

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
	"bytes"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
)

// SelectPivotListener - Interactive menu to select a pivot listener
func SelectPivotListener(listeners []*revilspb.PivotListener, con *console.RevilsConsoleClient) (*revilspb.PivotListener, error) {

	// Render selection table
	buf := bytes.NewBufferString("")
	table := tabwriter.NewWriter(buf, 0, 2, 2, ' ', 0)
	for _, listener := range listeners {
		fmt.Fprintf(table, "%d\t%s\t%s\t\n", listener.ID, PivotTypeToString(listener.Type), listener.BindAddress)
	}
	table.Flush()
	options := strings.Split(buf.String(), "\n")
	options = options[:len(options)-1]
	if len(options) == 0 {
		return nil, errors.New("no task to select from")
	}

	selected := ""
	prompt := &survey.Select{
		Message: "Select a beacon task:",
		Options: options,
	}
	err := survey.AskOne(prompt, &selected)
	if err != nil {
		return nil, err
	}
	for index, value := range options {
		if value == selected {
			return listeners[index], nil
		}
	}
	return nil, errors.New("task not found")
}
