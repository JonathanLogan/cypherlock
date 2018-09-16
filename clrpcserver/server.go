// Package clrpcserver implements client and server RPC methods to call github.com/JonathanLogan/cypherlock.
package clrpcserver

import (
	"github.com/JonathanLogan/cypherlock/ratchetserver"
	"github.com/JonathanLogan/cypherlock/types"
	"net"
	"net/http"
	"net/rpc"
)

// RPCServer implements a github.com/JonathanLogan/cypherlock rpc server over http(s).
type RPCServer struct {
	rpcmethods *RPCMethods
}

// NewRPCServer creates a new RPC server and starts it.
func NewRPCServer(server *ratchetserver.RatchetServer, listenAddr string) (*RPCServer, error) {
	rs := &RPCServer{
		rpcmethods: &RPCMethods{
			server: server,
		},
	}
	rs.rpcmethods.server.StartService()
	rpc.Register(rs.rpcmethods)
	rpc.HandleHTTP()
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go http.Serve(l, nil)
	return rs, nil
}

type RPCMethods struct {
	server *ratchetserver.RatchetServer
}

func (rm *RPCMethods) GetKeys(params types.RPCTypeNone, reply *types.RPCTypeGetKeysResponse) error {
	reply.Keys = rm.server.GetKeys()
	return nil
}

func (rm *RPCMethods) Decrypt(params types.RPCTypeDecrypt, reply *types.RPCTypeDecryptResponse) error {
	r, err := rm.server.Decrypt(params.OracleMessage)
	if err != nil {
		return err
	}
	reply.ResponseMessage = r
	return nil
}
