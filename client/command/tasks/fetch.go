package tasks

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
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Kevin-kitnick/revils/client/command/environment"
	"github.com/Kevin-kitnick/revils/client/command/exec"
	"github.com/Kevin-kitnick/revils/client/command/extensions"
	"github.com/Kevin-kitnick/revils/client/command/filesystem"
	"github.com/Kevin-kitnick/revils/client/command/network"
	"github.com/Kevin-kitnick/revils/client/command/privilege"
	"github.com/Kevin-kitnick/revils/client/command/processes"
	"github.com/Kevin-kitnick/revils/client/command/registry"
	"github.com/Kevin-kitnick/revils/client/command/settings"
	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/Kevin-kitnick/revils/util"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"google.golang.org/protobuf/proto"
)

// TasksFetchCmd - Manage beacon tasks
func TasksFetchCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	beacon := con.ActiveTarget.GetBeaconInteractive()
	if beacon == nil {
		return
	}
	beaconTasks, err := con.Rpc.GetBeaconTasks(context.Background(), &clientpb.Beacon{ID: beacon.ID})
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	tasks := beaconTasks.Tasks
	if len(tasks) == 0 {
		con.PrintErrorf("No tasks for beacon\n")
		return
	}

	idArg := ctx.Args.String("id")
	if idArg != "" {
		tasks = filterTasksByID(idArg, tasks)
		if len(tasks) == 0 {
			con.PrintErrorf("No beacon task found with id %s\n", idArg)
			return
		}
	}

	filter := ctx.Flags.String("filter")
	if filter != "" {
		tasks = filterTasksByTaskType(filter, tasks)
		if len(tasks) == 0 {
			con.PrintErrorf("No beacon tasks with filter type '%s'\n", filter)
			return
		}
	}

	var task *clientpb.BeaconTask
	if 1 < len(tasks) {
		task, err = SelectBeaconTask(tasks)
		if err != nil {
			con.PrintErrorf("%s\n", err)
			return
		}
		con.Printf(console.UpN+console.Clearln, 1)
	} else {
		task = tasks[0]
	}
	task, err = con.Rpc.GetBeaconTaskContent(context.Background(), &clientpb.BeaconTask{ID: task.ID})
	if err != nil {
		con.PrintErrorf("Failed to fetch task content: %s\n", err)
		return
	}
	PrintTask(task, con)
}

func filterTasksByID(taskID string, tasks []*clientpb.BeaconTask) []*clientpb.BeaconTask {
	filteredTasks := []*clientpb.BeaconTask{}
	for _, task := range tasks {
		if strings.HasPrefix(task.ID, strings.ToLower(taskID)) {
			filteredTasks = append(filteredTasks, task)
		}
	}
	return filteredTasks
}

func filterTasksByTaskType(taskType string, tasks []*clientpb.BeaconTask) []*clientpb.BeaconTask {
	filteredTasks := []*clientpb.BeaconTask{}
	for _, task := range tasks {
		if strings.HasPrefix(strings.ToLower(task.Description), strings.ToLower(taskType)) {
			filteredTasks = append(filteredTasks, task)
		}
	}
	return filteredTasks
}

// PrintTask - Print the details of a beacon task
func PrintTask(task *clientpb.BeaconTask, con *console.RevilsConsoleClient) {
	tw := table.NewWriter()
	tw.SetStyle(settings.GetTableWithBordersStyle(con))
	tw.AppendRow(table.Row{console.Bold + "Beacon Task" + console.Normal, task.ID})
	tw.AppendSeparator()
	tw.AppendRow(table.Row{"State", emojiState(task.State) + " " + prettyState(strings.Title(task.State))})
	tw.AppendRow(table.Row{"Description", task.Description})
	tw.AppendRow(table.Row{"Created", time.Unix(task.CreatedAt, 0).Format(time.RFC1123)})
	if !time.Unix(task.SentAt, 0).IsZero() {
		tw.AppendRow(table.Row{"Sent", time.Unix(task.SentAt, 0).Format(time.RFC1123)})
	}
	if !time.Unix(task.CompletedAt, 0).IsZero() {
		tw.AppendRow(table.Row{"Completed", time.Unix(task.CompletedAt, 0).Format(time.RFC1123)})
	}

	tw.AppendRow(table.Row{"Request Size", util.ByteCountBinary(int64(len(task.Request)))})
	if !time.Unix(task.CompletedAt, 0).IsZero() {
		tw.AppendRow(table.Row{"Response Size", util.ByteCountBinary(int64(len(task.Response)))})
	}
	tw.AppendSeparator()
	con.Printf("%s\n", tw.Render())
	if !time.Unix(task.CompletedAt, 0).IsZero() {
		con.Println()
		if 0 < len(task.Response) {
			renderTaskResponse(task, con)
		} else {
			con.PrintInfof("No task response\n")
		}
	}
}

func emojiState(state string) string {
	switch strings.ToLower(state) {
	case "completed":
		return "✅"
	case "pending":
		return "⏳"
	case "failed":
		return "❌"
	case "canceled":
		return "🚫"
	default:
		return "❓"
	}
}

// Decode and render message specific content
func renderTaskResponse(task *clientpb.BeaconTask, con *console.RevilsConsoleClient) {
	reqEnvelope := &revilspb.Envelope{}
	proto.Unmarshal(task.Request, reqEnvelope)
	switch reqEnvelope.Type {

	// ---------------------
	// Environment commands
	// ---------------------
	case revilspb.MsgEnvReq:
		envInfo := &revilspb.EnvInfo{}
		err := proto.Unmarshal(task.Response, envInfo)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		environment.PrintGetEnvInfo(envInfo, con)

	case revilspb.MsgSetEnvReq:
		setEnvReq := &revilspb.SetEnvReq{}
		err := proto.Unmarshal(task.Request, setEnvReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		setEnv := &revilspb.SetEnv{}
		err = proto.Unmarshal(task.Response, setEnv)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		environment.PrintSetEnvInfo(setEnvReq.Variable.Key, setEnvReq.Variable.Value, setEnv, con)

	case revilspb.MsgUnsetEnvReq:
		unsetEnvReq := &revilspb.UnsetEnvReq{}
		err := proto.Unmarshal(task.Request, unsetEnvReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		unsetEnv := &revilspb.UnsetEnv{}
		err = proto.Unmarshal(task.Response, unsetEnv)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		environment.PrintUnsetEnvInfo(unsetEnvReq.Name, unsetEnv, con)

	// ---------------------
	// Call extension commands
	// ---------------------
	case revilspb.MsgCallExtensionReq:
		callExtension := &revilspb.CallExtension{}
		err := proto.Unmarshal(task.Response, callExtension)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		extensions.PrintExtOutput("", "", callExtension, con)

	// ---------------------
	// Exec commands
	// ---------------------
	case revilspb.MsgInvokeExecuteAssemblyReq:
		fallthrough
	case revilspb.MsgInvokeInProcExecuteAssemblyReq:
		fallthrough
	case revilspb.MsgExecuteAssemblyReq:
		execAssembly := &revilspb.ExecuteAssembly{}
		err := proto.Unmarshal(task.Response, execAssembly)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, _ := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		hostname := "hostname"
		if beacon != nil {
			hostname = beacon.Hostname
		}
		assemblyPath := ""
		ctx := &grumble.Context{
			Command: &grumble.Command{Name: "execute-assembly"},
			Flags: grumble.FlagMap{
				"save": &grumble.FlagMapItem{Value: false, IsDefault: true},
				"loot": &grumble.FlagMapItem{Value: false, IsDefault: true},
				"name": &grumble.FlagMapItem{Value: "", IsDefault: true},
			},
		}
		exec.HandleExecuteAssemblyResponse(execAssembly, assemblyPath, hostname, ctx, con)

	// execute-shellcode
	case revilspb.MsgTaskReq:
		shellcodeExec := &revilspb.Task{}
		err := proto.Unmarshal(task.Response, shellcodeExec)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		exec.PrintExecuteShellcode(shellcodeExec, con)

	case revilspb.MsgExecuteReq:
		execReq := &revilspb.ExecuteReq{}
		err := proto.Unmarshal(reqEnvelope.Data, execReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		execResult := &revilspb.Execute{}
		err = proto.Unmarshal(task.Response, execResult)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		ctx := &grumble.Context{
			Flags: grumble.FlagMap{
				"ignore-stderr": &grumble.FlagMapItem{Value: false},
				"loot":          &grumble.FlagMapItem{Value: false},
				"stdout":        &grumble.FlagMapItem{Value: ""},
				"stderr":        &grumble.FlagMapItem{Value: ""},
				"output":        &grumble.FlagMapItem{Value: true},
			},
			Args: grumble.ArgMap{
				"command":   &grumble.ArgMapItem{Value: execReq.Path},
				"arguments": &grumble.ArgMapItem{Value: execReq.Args},
			},
		}
		exec.PrintExecute(execResult, ctx, con)

	case revilspb.MsgSideloadReq:
		sideload := &revilspb.Sideload{}
		err := proto.Unmarshal(task.Response, sideload)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, _ := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		hostname := "hostname"
		if beacon != nil {
			hostname = beacon.Hostname
		}
		ctx := &grumble.Context{
			Command: &grumble.Command{Name: "sideload"},
			Flags: grumble.FlagMap{
				"save": &grumble.FlagMapItem{Value: false},
				"loot": &grumble.FlagMapItem{Value: false},
			},
		}
		exec.HandleSideloadResponse(sideload, "", hostname, ctx, con)

	case revilspb.MsgSpawnDllReq:
		spawnDll := &revilspb.SpawnDll{}
		err := proto.Unmarshal(task.Response, spawnDll)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, _ := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		hostname := "hostname"
		if beacon != nil {
			hostname = beacon.Hostname
		}
		ctx := &grumble.Context{
			Command: &grumble.Command{Name: "spawndll"},
			Flags: grumble.FlagMap{
				"save": &grumble.FlagMapItem{Value: false},
				"loot": &grumble.FlagMapItem{Value: false},
			},
		}
		exec.HandleSpawnDLLResponse(spawnDll, "", hostname, ctx, con)

	case revilspb.MsgSSHCommandReq:
		sshCommand := &revilspb.SSHCommand{}
		err := proto.Unmarshal(task.Response, sshCommand)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		exec.PrintSSHCmd(sshCommand, con)

	// ---------------------
	// File system commands
	// ---------------------
	// Cat = download
	case revilspb.MsgCdReq:
		pwd := &revilspb.Pwd{}
		err := proto.Unmarshal(task.Response, pwd)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintPwd(pwd, con)

	case revilspb.MsgDownloadReq:
		download := &revilspb.Download{}
		err := proto.Unmarshal(task.Response, download)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		taskResponseDownload(download, con)

	case revilspb.MsgLsReq:
		ls := &revilspb.Ls{}
		err := proto.Unmarshal(task.Response, ls)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		flags := grumble.FlagMap{
			"reverse":  &grumble.FlagMapItem{Value: false},
			"modified": &grumble.FlagMapItem{Value: false},
			"size":     &grumble.FlagMapItem{Value: false},
		}
		filesystem.PrintLs(ls, flags, con)

	case revilspb.MsgMvReq:
		mv := &revilspb.Mv{}
		err := proto.Unmarshal(task.Response, mv)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}

	case revilspb.MsgMkdirReq:
		mkdir := &revilspb.Mkdir{}
		err := proto.Unmarshal(task.Response, mkdir)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintMkdir(mkdir, con)

	case revilspb.MsgPwdReq:
		pwd := &revilspb.Pwd{}
		err := proto.Unmarshal(task.Response, pwd)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintPwd(pwd, con)

	case revilspb.MsgRmReq:
		rm := &revilspb.Rm{}
		err := proto.Unmarshal(task.Response, rm)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintRm(rm, con)

	case revilspb.MsgUploadReq:
		upload := &revilspb.Upload{}
		err := proto.Unmarshal(task.Response, upload)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintUpload(upload, con)

	case revilspb.MsgChmodReq:
		chmod := &revilspb.Chmod{}
		err := proto.Unmarshal(task.Response, chmod)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintChmod(chmod, con)

	case revilspb.MsgChownReq:
		chown := &revilspb.Chown{}
		err := proto.Unmarshal(task.Response, chown)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintChown(chown, con)

	case revilspb.MsgChtimesReq:
		chtimes := &revilspb.Chtimes{}
		err := proto.Unmarshal(task.Response, chtimes)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintChtimes(chtimes, con)

	case revilspb.MsgMemfilesListReq:
		memfilesList := &revilspb.Ls{}
		err := proto.Unmarshal(task.Response, memfilesList)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintMemfiles(memfilesList, con)

	case revilspb.MsgMemfilesAddReq:
		memfilesAdd := &revilspb.MemfilesAdd{}
		err := proto.Unmarshal(task.Response, memfilesAdd)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintAddMemfile(memfilesAdd, con)

	case revilspb.MsgMemfilesRmReq:
		memfilesRm := &revilspb.MemfilesRm{}
		err := proto.Unmarshal(task.Response, memfilesRm)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintRmMemfile(memfilesRm, con)

	// ---------------------
	// Network commands
	// ---------------------
	case revilspb.MsgIfconfigReq:
		ifconfig := &revilspb.Ifconfig{}
		err := proto.Unmarshal(task.Response, ifconfig)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		network.PrintIfconfig(ifconfig, true, con)

	case revilspb.MsgNetstsatReq:
		netstat := &revilspb.Netstat{}
		err := proto.Unmarshal(task.Response, netstat)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to fetch beacon: %s\n", err)
			return
		}
		network.PrintNetstat(netstat, beacon.PID, beacon.ActiveC2, false, con)

	// ---------------------
	// Privilege commands
	// ---------------------
	case revilspb.MsgGetPrivsReq:
		privs := &revilspb.GetPrivs{}
		err := proto.Unmarshal(task.Response, privs)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to fetch beacon: %s\n", err)
			return
		}
		privilege.PrintGetPrivs(privs, beacon.PID, con)

	case revilspb.MsgInvokeGetSystemReq:
		getSystem := &revilspb.GetSystem{}
		err := proto.Unmarshal(task.Response, getSystem)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		privilege.PrintGetSystem(getSystem, con)

	case revilspb.MsgCurrentTokenOwnerReq:
		cto := &revilspb.CurrentTokenOwner{}
		err := proto.Unmarshal(task.Response, cto)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}

	case revilspb.MsgImpersonateReq:
		impersonateReq := &revilspb.ImpersonateReq{}
		err := proto.Unmarshal(task.Response, impersonateReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		impersonate := &revilspb.Impersonate{}
		err = proto.Unmarshal(task.Response, impersonate)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		privilege.PrintImpersonate(impersonate, impersonateReq.Username, con)

	case revilspb.MsgMakeTokenReq:
		makeTokenReq := &revilspb.MakeTokenReq{}
		err := proto.Unmarshal(task.Response, makeTokenReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		makeToken := &revilspb.MakeToken{}
		err = proto.Unmarshal(task.Response, makeToken)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		privilege.PrintMakeToken(makeToken, makeTokenReq.Domain, makeTokenReq.Username, con)

	case revilspb.MsgRunAsReq:
		runAsReq := &revilspb.RunAsReq{}
		err := proto.Unmarshal(task.Response, runAsReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		runAs := &revilspb.RunAs{}
		err = proto.Unmarshal(task.Response, runAs)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to fetch beacon: %s\n", err)
			return
		}
		privilege.PrintRunAs(runAs, runAsReq.ProcessName, runAsReq.Args, beacon.Name, con)

	// ---------------------
	// Processes commands
	// ---------------------
	case revilspb.MsgProcessDumpReq:
		dump := &revilspb.ProcessDump{}
		err := proto.Unmarshal(task.Response, dump)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		promptSaveToFile(dump.Data, con)

	case revilspb.MsgPsReq:
		ps := &revilspb.Ps{}
		err := proto.Unmarshal(task.Response, ps)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to get beacon: %s\n", err)
			return
		}
		ctx := &grumble.Context{
			Flags: grumble.FlagMap{
				"pid":           &grumble.FlagMapItem{Value: -1},
				"exe":           &grumble.FlagMapItem{Value: ""},
				"owner":         &grumble.FlagMapItem{Value: ""},
				"overflow":      &grumble.FlagMapItem{Value: false},
				"skip-pages":    &grumble.FlagMapItem{Value: 0},
				"print-cmdline": &grumble.FlagMapItem{Value: true},
				"tree":          &grumble.FlagMapItem{Value: false},
			},
		}
		processes.PrintPS(beacon.OS, ps, true, ctx, con)

	case revilspb.MsgTerminateReq:
		terminate := &revilspb.Terminate{}
		err := proto.Unmarshal(task.Response, terminate)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		processes.PrintTerminate(terminate, con)

	// ---------------------
	// Registry commands
	// ---------------------
	case revilspb.MsgRegistryCreateKeyReq:
		createKeyReq := &revilspb.RegistryCreateKeyReq{}
		err := proto.Unmarshal(task.Request, createKeyReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		createKey := &revilspb.RegistryCreateKey{}
		err = proto.Unmarshal(task.Response, createKey)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintCreateKey(createKey, createKeyReq.Path, createKeyReq.Key, con)

	case revilspb.MsgRegistryDeleteKeyReq:
		deleteKeyReq := &revilspb.RegistryDeleteKeyReq{}
		err := proto.Unmarshal(task.Request, deleteKeyReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		deleteKey := &revilspb.RegistryDeleteKey{}
		err = proto.Unmarshal(task.Response, deleteKey)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintDeleteKey(deleteKey, deleteKeyReq.Path, deleteKeyReq.Key, con)

	case revilspb.MsgRegistryListValuesReq:
		listValuesReq := &revilspb.RegistryListValuesReq{}
		err := proto.Unmarshal(task.Request, listValuesReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		regList := &revilspb.RegistryValuesList{}
		err = proto.Unmarshal(task.Response, regList)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintListValues(regList, listValuesReq.Hive, listValuesReq.Path, con)

	case revilspb.MsgRegistrySubKeysListReq:
		listValuesReq := &revilspb.RegistrySubKeyListReq{}
		err := proto.Unmarshal(task.Request, listValuesReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		regList := &revilspb.RegistrySubKeyList{}
		err = proto.Unmarshal(task.Response, regList)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintListSubKeys(regList, listValuesReq.Hive, listValuesReq.Path, con)

	case revilspb.MsgRegistryReedReq:
		regRead := &revilspb.RegistryRead{}
		err := proto.Unmarshal(task.Response, regRead)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintRegRead(regRead, con)

	case revilspb.MsgRegistryWriteReq:
		regWrite := &revilspb.RegistryWrite{}
		err := proto.Unmarshal(task.Response, regWrite)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintRegWrite(regWrite, con)

	// ---------------------
	// Screenshot
	// ---------------------
	case revilspb.MsgScreenshotReq:
		screenshot := &revilspb.Screenshot{}
		err := proto.Unmarshal(task.Response, screenshot)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		promptSaveToFile(screenshot.Data, con)

	// ---------------------
	// Default
	// ---------------------
	default:
		con.PrintErrorf("Cannot render task response for msg type %v\n", reqEnvelope.Type)
	}
}

func taskResponseDownload(download *revilspb.Download, con *console.RevilsConsoleClient) {
	const (
		dump   = "Dump Contents"
		saveTo = "Save to File ..."
	)
	action := saveTo
	prompt := &survey.Select{
		Message: "Choose an option:",
		Options: []string{dump, saveTo},
	}
	err := survey.AskOne(prompt, &action, survey.WithValidator(survey.Required))
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	switch action {
	case dump:
		con.Printf("%s\n", string(download.Data))
	default:
		promptSaveToFile(download.Data, con)
	}
}

func promptSaveToFile(data []byte, con *console.RevilsConsoleClient) {
	saveTo := ""
	saveToPrompt := &survey.Input{Message: "Save to: "}
	err := survey.AskOne(saveToPrompt, &saveTo)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	if _, err := os.Stat(saveTo); !os.IsNotExist(err) {
		confirm := false
		prompt := &survey.Confirm{Message: "Overwrite existing file?"}
		survey.AskOne(prompt, &confirm)
		if !confirm {
			return
		}
	}
	err = ioutil.WriteFile(saveTo, data, 0600)
	if err != nil {
		con.PrintErrorf("Failed to save file: %s\n", err)
		return
	}
	con.PrintInfof("Wrote %d byte(s) to %s", len(data), saveTo)
}
