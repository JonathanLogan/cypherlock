package types

// RPCTypeNone is an empty RPC type to fullfil API requirements.
type RPCTypeNone struct{}

// RPCTypeGetKeysResponse is the response by a github.com/JonathanLogan/cypherlock server containing a binary keylist.
type RPCTypeGetKeysResponse struct {
	Keys []byte
}

// RPCTypeDecrypt is the request for a github.com/JonathanLogan/cypherlock server to decrypt the contained binary OracleMessage.
type RPCTypeDecrypt struct {
	OracleMessage []byte
}

// ResponeMessage is the response from a github.com/JonathanLogan/cypherlock server that contains the binary ResponseMessage.
type RPCTypeDecryptResponse struct {
	ResponseMessage []byte
}
