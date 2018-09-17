// Package clientinterface implements an interface to read and write client data.
package clientinterface

import (
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/JonathanLogan/cypherlock/types"
)

// Storage is the interface to be implemented by storage backends.
type Storage interface {
	StoreLock(filename string, data []byte) error     // Store a lock.
	GetLock(now uint64) (data []byte, err error)      // Return a matching lock.
	StoreKeylist(keys *types.RatchetList) error       // Store a keylist.
	GetKeylist() (keys *types.RatchetList, err error) // Read a keylist.
	StoreSecret(data []byte) error                    // Store a secret.
	GetSecret() (data []byte, err error)              // Load a secret.
}

// DefaultStorage is the default file-backed storage.
type DefaultStorage struct {
	Path string // Storage path
}

// StoreLock stores a lock.
func (ds DefaultStorage) StoreLock(filename string, data []byte) error {
	return ds.writeFile(filename, data)
}

func (ds DefaultStorage) writeFile(filename string, data []byte) error {
	os.MkdirAll(ds.Path, 0700)
	p := path.Join(ds.Path, filename)
	return ioutil.WriteFile(p, data, 0600)
}

func (ds DefaultStorage) readFile(filename string) ([]byte, error) {
	filenameX := path.Join(ds.Path, filename)
	return ioutil.ReadFile(filenameX)
}

func parseFilename(fn string) (validFrom, validTo uint64, ok bool) {
	pos := strings.LastIndex(fn, ".oracle")
	if pos < 3 {
		return 0, 0, false
	}
	subs := strings.Split(fn[0:pos], "-")
	if len(subs) != 2 {
		return 0, 0, false
	}
	validFrom, err := strconv.ParseUint(subs[0], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	validTo, err = strconv.ParseUint(subs[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return validFrom, validTo, true
}

// GetLock returns a matching lock.
func (ds DefaultStorage) GetLock(now uint64) (data []byte, err error) {
	var filename string
	entries, err := ioutil.ReadDir(ds.Path)
	if err != nil {
		return nil, err
	}
FilterLoop:
	for _, e := range entries {
		if e.IsDir() {
			continue FilterLoop
		}
		name := e.Name()
		if name == "keylist" || name == "secret" {
			continue FilterLoop
		}
		validFrom, validTo, ok := parseFilename(name)
		if ok {
			if validFrom <= now && validTo >= now {
				filename = name
				break FilterLoop
			}
		}
	}
	return ds.readFile(filename)
}

// StoreKeylist stores a keylist.
func (ds DefaultStorage) StoreKeylist(keys *types.RatchetList) error {
	filename := "keylist"
	data := keys.Bytes()
	return ds.StoreLock(filename, data)
}

// GetKeylist reads a keylist.
func (ds DefaultStorage) GetKeylist() (keys *types.RatchetList, err error) {
	data, err := ds.readFile("keylist")
	if err != nil {
		return nil, err
	}
	return new(types.RatchetList).Parse(data)
}

// StoreSecret stores a secret.
func (ds DefaultStorage) StoreSecret(data []byte) error {
	filename := "secret"
	return ds.StoreLock(filename, data)
}

// GetSecret loads a secret.
func (ds DefaultStorage) GetSecret() (data []byte, err error) {
	return ds.readFile("secret")
}
