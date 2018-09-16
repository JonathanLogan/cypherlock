package ratchetserver

import (
	"io/ioutil"
	"os"
	"path"
)

// Storage layer.

// StoreType is the type of data to store.
type StoreType int

const (
	// StoreTypeServerKeys for ServerKeys.
	StoreTypeServerKeys = iota
	// StoreTypeFountain for Fountain data.
	StoreTypeFountain
	// StoreTypePregen for pregenerator config.
	StoreTypePregen
	// StoreTypeKeyList for the pregenerated key list.
	StoreTypeKeyList
)

type Persistence interface {
	Store(storeType StoreType, data []byte) error // Write data of type StoreType to persistant storage.
	Load(storeType StoreType) ([]byte, error)     // Load data of type StoreType from persistant storage.
}

// DummyFileStore is trivial storage to files.
type DummyFileStore struct {
	Path string // filesystem path, directory.
}

func (dfs *DummyFileStore) getFileName(storeType StoreType) string {
	var fn string
	if dfs.Path == "" {
		dfs.Path, _ = ioutil.TempDir("", "github.com/JonathanLogan/cypherlock.") // Ignore error.
	}
	switch storeType {
	case StoreTypeServerKeys:
		fn = "server.keys"
	case StoreTypeFountain:
		fn = "fountain.state"
	case StoreTypePregen:
		fn = "pregenerator.state"
	case StoreTypeKeyList:
		fn = "keys.list"
	default:
		panic("Unknown storage type.")
	}
	return path.Join(dfs.Path, fn)
}

// Create directory if not exist.
func (dfs *DummyFileStore) mkDir() error {
	return os.MkdirAll(dfs.Path, 0700)
}

// Store data.
func (dfs *DummyFileStore) Store(storeType StoreType, data []byte) error {
	dfs.mkDir() // Ignore errors.
	fn := dfs.getFileName(storeType)
	return ioutil.WriteFile(fn, data, 0600)
}

// Load data.
func (dfs *DummyFileStore) Load(storeType StoreType) ([]byte, error) {
	fn := dfs.getFileName(storeType)
	return ioutil.ReadFile(fn)
}
