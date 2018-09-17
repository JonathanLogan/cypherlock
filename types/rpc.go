package types

// RPCTypeNone is an empty RPC type to fullfil API requirements.
type RPCTypeNone struct{}

// RPCTypeGetKeysResponse is the response by a Cypherlock server containing a binary keylist.
type RPCTypeGetKeysResponse struct {
	Keys []byte
}

// RPCTypeDecrypt is the request for a Cypherlock server to decrypt the contained binary OracleMessage.
type RPCTypeDecrypt struct {
	OracleMessage []byte
}

// RPCTypeDecryptResponse is the response from a Cypherlock server that contains the binary ResponseMessage.
type RPCTypeDecryptResponse struct {
	ResponseMessage []byte
}
