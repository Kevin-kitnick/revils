package constants

import "reflect"

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

// Ironically not consts to ensure the string obfuscator hits this value
var (
	RevilsName = `{{.Name}}`
)

// Message - Fake message for embedding canaries
type Message struct {
	Command string `c2:"[[GenerateCanary]]"`
}

// never obfuscate the Message type
var _ = reflect.TypeOf(Message{})
