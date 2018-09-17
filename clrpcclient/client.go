// Package clrpcclient implements client RPC methods for Cypherlock access.
package clrpcclient

import (
	"net/rpc"

	"github.com/JonathanLogan/cypherlock/types"
)

// RPCClient is a Cypherlock RPC client.
type RPCClient struct {
	rpc *rpc.Client
}

// NewRPCClient connects and returns an rpcclient, addr is "host:port".
func NewRPCClient(addr string) (*RPCClient, error) {
	client, err := rpc.DialHTTP("tcp", addr)
	if err != nil {
		return nil, err
	}
	rc := &RPCClient{
		rpc: client,
	}
	return rc, nil
}

// GetKeys returns a binary list of keys from the server.
func (rc *RPCClient) GetKeys() ([]byte, error) {
	resp := new(types.RPCTypeGetKeysResponse)
	err := rc.rpc.Call("RPCMethods.GetKeys", new(types.RPCTypeNone), resp)
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// Decrypt an oraclemessage.
func (rc *RPCClient) Decrypt(msg []byte) ([]byte, error) {
	resp := new(types.RPCTypeDecryptResponse)
	params := &types.RPCTypeDecrypt{
		OracleMessage: msg,
	}
	err := rc.rpc.Call("RPCMethods.Decrypt", params, resp)
	if err != nil {
		return nil, err
	}
	return resp.ResponseMessage, nil
}
