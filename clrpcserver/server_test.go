package clrpcserver

import (
	"github.com/JonathanLogan/cypherlock/clrpcclient"
	"github.com/JonathanLogan/cypherlock/ratchetserver"
	"crypto/rand"
	"testing"
)

func TestServer(t *testing.T) {
	persistence := &ratchetserver.DummyFileStore{
		Path: "/tmp/github.com/JonathanLogan/cypherlock/",
	}
	ratchetServer, err := ratchetserver.NewRatchetServer(persistence, rand.Reader, 3600, 24*3600)
	if err != nil {
		t.Fatalf("NewRatchetServer: %s", err)
	}
	rpcServer, err := NewRPCServer(ratchetServer, "127.0.0.1:9443")
	if err != nil {
		t.Fatalf("NewRPCServer: %s", err)
	}

	rpcClient, err := clrpcclient.NewRPCClient("127.0.0.1:9443")
	if err != nil {
		t.Fatalf("NewRPCClient: %s", err)
	}
	keys, err := rpcClient.GetKeys()
	if err != nil {
		t.Fatalf("GetKeys: %s", err)
	}
	rspmsg, err := rpcClient.Decrypt([]byte("nothing"))
	if err == nil {
		t.Error("Decrypt should fail")
	}
	_, _, _ = rpcServer, keys, rspmsg
}
