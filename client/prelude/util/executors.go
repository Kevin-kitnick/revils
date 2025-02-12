package util

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

func DetermineExecutors(platform string, arch string) []string {
	platformExecutors := map[string]map[string][]string{
		"windows": {
			"file":     {"pwsh.exe", "powershell.exe", "cmd.exe", "", ""},
			"executor": {"pwsh", "psh", "cmd", "bof", "exec"},
		},
		"linux": {
			"file":     {"python3", "sh", "bash"},
			"executor": {"python", "sh", "bash"},
		},
		"darwin": {
			"file":     {"python3", "zsh", "sh", "osascript", "bash"},
			"executor": {"python", "zsh", "sh", "osa", "bash"},
		},
	}
	var executors []string
	for platformKey, platformValue := range platformExecutors {
		if platform == platformKey {
			for i := range platformValue["file"] {
				executors = append(executors, platformExecutors[platformKey]["executor"][i])
			}
		}
	}
	executors = append([]string{"keyword"}, executors...)
	return executors
}
