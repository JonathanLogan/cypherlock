## Cypherlock

[![GoDoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://godoc.org/github.com/JonathanLogan/cypherlock) [![Build Status](https://travis-ci.com/JonathanLogan/cypherlock.svg?branch=master&style=flat-square)](https://travis-ci.org/JonathanLogan/cypherlock) [![Go Report Card](https://goreportcard.com/badge/github.com/JonathanLogan/cypherlock?style=flat-square)](https://goreportcard.com/report/github.com/JonathanLogan/cypherlock)

Ratchet based key expiry tool against forced decryption and for expiring
backups.

Requirements:
 - Linux knowledge
 - Raspberry Pi

### Installation

```
go get -u -v github.com/JonathanLogan/cypherlock/cmd/...
```

### Usage

First we create a new Cypherlock server:

```
$ cypherlockd -create
cypherlockd: minimal Cypherlock server
Server created.
SignatureKey: 8ad30073d3b5090eae94715304ec0916ea77bde2b3c3512e51ac55453bbe0c77

```

Then we let it run on the default interface (change interface with `-addr`):

```
$ cypherlockd -serve
cypherlockd: minimal Cypherlock server
Serving...
SignatureKey: 8ad30073d3b5090eae94715304ec0916ea77bde2b3c3512e51ac55453bbe0c77
```

Now we want to encrypt a time-locked `secret` file:

```
$ exec 3<secret; cypherlock -create -sigkey 8ad30073d3b5090eae94715304ec0916ea77bde2b3c3512e51ac55453bbe0c77
Please enter passphrase (no echo):
Please repeat passphrase (no echo):

Lock created. From "Wed Sep 19 22:40:27 +0000 UTC 2018" to "Wed Sep 19 23:10:27 +0000 UTC 2018"
```

To unlock the time-locked secret via the Cypherlock server and store it in file `secret2`:
```
$ exec 3>secret2; cypherlock -unlock -sigkey 8ad30073d3b5090eae94715304ec0916ea77bde2b3c3512e51ac55453bbe0c77
Please enter passphrase (no echo):
```

Now we have the content of the original `secret` file in `secret2`.

### Presentations

- [Cypherlock at BalCCon2k18](doc/Cypherlock-BalCCon2k18.pdf)
