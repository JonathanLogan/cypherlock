package clientinterface

import (
	"github.com/JonathanLogan/cypherlock/clrpcclient"
	"github.com/JonathanLogan/cypherlock/types"
)

// ClientRPC is the interface to make calls to the github.com/JonathanLogan/cypherlock.
type ClientRPC interface {
	GetKeylist(serverURL string) (*types.RatchetList, error)
	Decrypt(serverURL string, oracleMessage []byte) (responseMessage []byte, err error)
}

// DefaultRPC is the default implementation for RPC.
type DefaultRPC struct {
}

// GetKeylist returns the keylist from a server.
func (dr *DefaultRPC) GetKeylist(serverURL string) (*types.RatchetList, error) {
	rpclient, err := clrpcclient.NewRPCClient(serverURL)
	if err != nil {
		return nil, err
	}
	klB, err := rpclient.GetKeys()
	if err != nil {
		return nil, err
	}
	return new(types.RatchetList).Parse(klB)
}

// Decrypt an oracleMessage at the serverURL.
func (dr *DefaultRPC) Decrypt(serverURL string, oracleMessage []byte) (responseMessage []byte, err error) {
	rpclient, err := clrpcclient.NewRPCClient(serverURL)
	if err != nil {
		return nil, err
	}
	return rpclient.Decrypt(oracleMessage)
}
