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

	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
)

// RegistryRead - gRPC interface to read a registry key from a session
func (rpc *Server) RegistryRead(ctx context.Context, req *revilspb.RegistryReedReq) (*revilspb.RegistryRead, error) {
	resp := &revilspb.RegistryRead{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryWrite - gRPC interface to write to a registry key on a session
func (rpc *Server) RegistryWrite(ctx context.Context, req *revilspb.RegistryWriteReq) (*revilspb.RegistryWrite, error) {
	resp := &revilspb.RegistryWrite{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryCreateKey - gRPC interface to create a registry key on a session
func (rpc *Server) RegistryCreateKey(ctx context.Context, req *revilspb.RegistryCreateKeyReq) (*revilspb.RegistryCreateKey, error) {
	resp := &revilspb.RegistryCreateKey{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryDeleteKey - gRPC interface to delete a registry key on a session
func (rpc *Server) RegistryDeleteKey(ctx context.Context, req *revilspb.RegistryDeleteKeyReq) (*revilspb.RegistryDeleteKey, error) {
	resp := &revilspb.RegistryDeleteKey{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryListSubKeys - gRPC interface to list the sub keys of a registry key
func (rpc *Server) RegistryListSubKeys(ctx context.Context, req *revilspb.RegistrySubKeyListReq) (*revilspb.RegistrySubKeyList, error) {
	resp := &revilspb.RegistrySubKeyList{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryListSubKeys - gRPC interface to list the sub keys of a registry key
func (rpc *Server) RegistryListValues(ctx context.Context, req *revilspb.RegistryListValuesReq) (*revilspb.RegistryValuesList, error) {
	resp := &revilspb.RegistryValuesList{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
