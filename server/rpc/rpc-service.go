package rpc

import (
	"context"

	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
)

// StartService creates and starts a Windows service on a remote host
func (rpc *Server) StartService(ctx context.Context, req *revilspb.StartServiceReq) (*revilspb.ServiceInfo, error) {
	resp := &revilspb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StopService stops a remote service
func (rpc *Server) StopService(ctx context.Context, req *revilspb.StopServiceReq) (*revilspb.ServiceInfo, error) {
	resp := &revilspb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RemoveService deletes a service from the remote system
func (rpc *Server) RemoveService(ctx context.Context, req *revilspb.RemoveServiceReq) (*revilspb.ServiceInfo, error) {
	resp := &revilspb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
