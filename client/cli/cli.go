package cli

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
	"fmt"
	"log"
	"os"
	"path"

	"github.com/Kevin-kitnick/revils/client/assets"
	"github.com/Kevin-kitnick/revils/client/command"
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/client/transport"
	"github.com/Kevin-kitnick/revils/client/version"

	"github.com/spf13/cobra"
)

const (
	logFileName = "revils-client.log"
)

var (
	revilsServerVersion = fmt.Sprintf("v%s", version.FullVersion())
)

// Initialize logging
func initLogging(appDir string) *os.File {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	logFile, err := os.OpenFile(path.Join(appDir, logFileName), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		panic(fmt.Sprintf("[!] Error opening file: %s", err))
	}
	log.SetOutput(logFile)
	return logFile
}

func init() {

	// Import
	rootCmd.AddCommand(cmdImport)

	// Version
	rootCmd.AddCommand(cmdVersion)
}

var rootCmd = &cobra.Command{
	Use:   "revils-client",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		appDir := assets.GetRootAppDir()
		logFile := initLogging(appDir)
		defer logFile.Close()

		os.Args = os.Args[:1] // Stops grumble from complaining
		err := StartClientConsole()
		if err != nil {
			fmt.Printf("[!] %s\n", err)
		}
	},
}

// StartClientConsole - Start the client console
func StartClientConsole() error {
	configs := assets.GetConfigs()
	if len(configs) == 0 {
		fmt.Printf("No config files found at %s (see --help)\n", assets.GetConfigDir())
		return nil
	}
	config := selectConfig()
	if config == nil {
		return nil
	}

	fmt.Printf("Connecting to %s:%d ...\n", config.LHost, config.LPort)
	rpc, ln, err := transport.MTLSConnect(config)
	if err != nil {
		fmt.Printf("Connection to server failed %s", err)
		return nil
	}
	defer ln.Close()
	return console.Start(rpc, command.BindCommands, func(con *console.RevilsConsoleClient) {}, false)
}

// Execute - Execute root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
