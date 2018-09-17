// cypherlock implements a Cypherlock client.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
	"unicode"

	"github.com/JonathanLogan/cypherlock/clientinterface"
	"github.com/JonathanLogan/cypherlock/msgcrypt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	flagSignatureKey   string
	flagServerURL      string
	flagPath           string
	flagValidFrom      uint64
	flagValidTo        uint64
	flagFD             int
	flagNL             bool
	flagFunctionExtend bool
	flagFunctionCreate bool
	flagFunctionUnlock bool
	now                uint64
)

func init() {
	now = uint64(time.Now().Unix())
	flag.BoolVar(&flagFunctionExtend, "extend", false, "extend existing github.com/JonathanLogan/cypherlock")
	flag.BoolVar(&flagFunctionCreate, "create", false, "create new github.com/JonathanLogan/cypherlock")
	flag.BoolVar(&flagFunctionUnlock, "unlock", false, "unlock github.com/JonathanLogan/cypherlock")
	flag.BoolVar(&flagNL, "nl", false, "add newline to secret when writing")

	flag.StringVar(&flagPath, "path", "/tmp/github.com/JonathanLogan/cypherlock", "path to store lock")
	flag.StringVar(&flagServerURL, "server", "127.0.0.1:11139", "github.com/JonathanLogan/cypherlockd server [IP:Port]")
	flag.StringVar(&flagSignatureKey, "sigkey", "", "github.com/JonathanLogan/cypherlockd signature key. Required for -create and -extend")

	flag.Uint64Var(&flagValidFrom, "from", now, "earliest unix timestamp at which the lock is valid")
	flag.Uint64Var(&flagValidTo, "to", now+1800, "earliest unix timestamp at which the lock is valid")
	flag.IntVar(&flagFD, "fd", 3, "file descriptor to read/write secret from. Required for -create and -unlock")

	flag.Parse()
}

func writeSecret(s []byte) {
	q := s
	if flagNL {
		q = append(q, '\n')
	}
	file := os.NewFile(uintptr(flagFD), "pipe")
	defer file.Close()
	_, err := file.Write(q)
	if err != nil {
		fmt.Printf("ERR: %s\n", err)
		os.Exit(1)
	}
}

func readSecret() []byte {
	d := make([]byte, 500)
	file := os.NewFile(uintptr(flagFD), "pipe")
	defer file.Close()
	n, err := file.Read(d)
	if n == 0 && err != nil {
		fmt.Printf("ERR: %s\n", err)
		os.Exit(1)
	}
	return bytes.TrimFunc(d[:n], unicode.IsSpace)
}

func getSigKey() *[ed25519.PublicKeySize]byte {
	sigKey := new([ed25519.PublicKeySize]byte)
	if len(flagSignatureKey) == 0 {
		fmt.Println("Must give -sigkey.")
		os.Exit(1)
	}
	sigKeyB, err := hex.DecodeString(flagSignatureKey)
	if err != nil {
		fmt.Printf("ERR: %s\n", err)
		os.Exit(1)
	}
	copy(sigKey[:], sigKeyB)
	return sigKey
}

func getPassphraseOnce(prompt string, fd int) []byte {
	if !terminal.IsTerminal(fd) {
		fmt.Println("ERR: Not a terminal.")
		os.Exit(1)
	}
	fmt.Printf("%s: ", prompt)
	state, err := terminal.GetState(fd)
	if err != nil {
		fmt.Printf("ERR: %s\n", err)
		os.Exit(1)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		terminal.Restore(fd, state)
		fmt.Println("\ncancelled")
		os.Exit(1)
	}()
	p, err := terminal.ReadPassword(fd)
	if err != nil {
		fmt.Printf("ERR: %s\n", err)
		os.Exit(1)
	}
	signal.Stop(c)
	fmt.Print("\n")
	return bytes.TrimFunc(p, unicode.IsSpace)
}

func getPassphrase() []byte {
	var p1 []byte
	fd := 0
RequestLoop:
	for {
		p1 = getPassphraseOnce("Please enter passphrase (no echo)", fd)
		if len(p1) == 0 {
			fmt.Println("empty passphrase, please repeat.")
			continue RequestLoop
		}
		p2 := getPassphraseOnce("Please repeat passphrase (no echo)", fd)
		if bytes.Equal(p1, p2) {
			break RequestLoop
		}
		fmt.Print("Passphrases dont match.\n")
	}
	fmt.Print("\n")
	return p1
}

const timeFormat = "Mon Jan 2 15:04:05 -0700 MST 2006"

func main() {
	if !(flagFunctionExtend || flagFunctionCreate || flagFunctionUnlock) {
		fmt.Println("One of -extend , -create or -unlock required.")
		os.Exit(1)
	}
	if (flagFunctionExtend && (flagFunctionCreate || flagFunctionUnlock)) ||
		(flagFunctionCreate && (flagFunctionExtend || flagFunctionUnlock)) ||
		(flagFunctionUnlock && (flagFunctionExtend || flagFunctionCreate)) {
		fmt.Println("Only one of -extend , -create or -unlock allowed.")
		os.Exit(1)
	}
	Config := &msgcrypt.Cypherlock{
		ServerURL: flagServerURL,
		Storage:   &clientinterface.DefaultStorage{Path: flagPath},
		ClientRPC: new(clientinterface.DefaultRPC),
	}
	if flagFunctionCreate || flagFunctionExtend {
		Config.SignatureKey = getSigKey()

	}
	if flagFunctionCreate || flagFunctionUnlock {
		if flagFD < 3 {
			fmt.Println("ERR: fd must be 3 or higher.")
			os.Exit(1)
		}
	}
	if flagFunctionCreate {
		passphrase := getPassphrase()
		secret := readSecret()
		validFrom, validTo, err := Config.CreateLock(passphrase, secret, flagValidFrom, flagValidTo)
		if err != nil {
			fmt.Printf("ERR: %s\n", err)
			os.Exit(1)
		}
		validFromT, validToT := time.Unix(int64(validFrom), 0).Format(timeFormat), time.Unix(int64(validTo), 0).Format(timeFormat)
		fmt.Printf("Lock created. From \"%s\" to \"%s\"\n", validFromT, validToT)
		os.Exit(0)
	}
	passphrase := getPassphraseOnce("Please enter passphrase (no echo)", 0)
	if flagFunctionExtend {
		validFrom, validTo, err := Config.ExtendLock(passphrase, now, flagValidFrom, flagValidTo)
		if err != nil {
			fmt.Printf("ERR: %s\n", err)
			os.Exit(1)
		}
		validFromT, validToT := time.Unix(int64(validFrom), 0).Format(timeFormat), time.Unix(int64(validTo), 0).Format(timeFormat)
		fmt.Printf("Lock extended. From \"%s\" to \"%s\"\n", validFromT, validToT)
		os.Exit(0)
	}
	if flagFunctionUnlock {
		realSecret, err := Config.LoadLock(passphrase, now)
		if err != nil {
			fmt.Printf("ERR: %s\n", err)
			os.Exit(1)
		}
		writeSecret(realSecret)
		_ = realSecret
		os.Exit(0)
	}
}
