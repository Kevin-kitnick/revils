package reaction

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
	"errors"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/client/core"
	"github.com/desertbit/grumble"
)

var (
	// ErrNonReactableEvent - Event does not exist or is not supported by reactions
	ErrNonReactableEvent = errors.New("non-reactable event type")
)

// ReactionSetCmd - Set a reaction upon an event
func ReactionSetCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	eventType, err := getEventType(ctx, con)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	con.Println()
	con.PrintInfof("Setting reaction to: %s\n", EventTypeToTitle(eventType))
	con.Println()
	rawCommands, err := userCommands()
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	commands := []string{}
	for _, rawCommand := range strings.Split(rawCommands, "\n") {
		if rawCommand != "" {
			commands = append(commands, rawCommand)
		}
	}

	reaction := core.Reactions.Add(core.Reaction{
		EventType: eventType,
		Commands:  commands,
	})

	con.Println()
	con.PrintInfof("Set reaction to %s (id: %d)\n", eventType, reaction.ID)
}

func getEventType(ctx *grumble.Context, con *console.RevilsConsoleClient) (string, error) {
	rawEventType := ctx.Flags.String("event")
	if rawEventType == "" {
		return selectEventType(con)
	} else {
		for _, eventType := range core.ReactableEvents {
			if eventType == rawEventType {
				return eventType, nil
			}
		}
		return "", ErrNonReactableEvent
	}
}

func selectEventType(con *console.RevilsConsoleClient) (string, error) {
	prompt := &survey.Select{
		Message: "Select an event:",
		Options: core.ReactableEvents,
	}
	selection := ""
	err := survey.AskOne(prompt, &selection)
	if err != nil {
		return "", err
	}
	for _, eventType := range core.ReactableEvents {
		if eventType == selection {
			return eventType, nil
		}
	}
	return "", ErrNonReactableEvent
}

func userCommands() (string, error) {
	text := ""
	prompt := &survey.Multiline{
		Message: "Enter commands: ",
	}
	err := survey.AskOne(prompt, &text)
	return text, err
}
