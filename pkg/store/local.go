package store

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/harmony-one/go-sdk/pkg/address"
	"github.com/harmony-one/go-sdk/pkg/common"
	c "github.com/harmony-one/go-sdk/pkg/common"
	"github.com/harmony-one/harmony/accounts"
	"github.com/harmony-one/harmony/accounts/keystore"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
)

func init() {
	uDir, _ := homedir.Dir()
	hmyAccDir := path.Join(uDir, common.DefaultConfigDirName, common.DefaultConfigAccountAliasesDirName)
	if _, err := os.Stat(hmyAccDir); os.IsNotExist(err) {
		os.MkdirAll(hmyAccDir, 0700)
	}
	hmyBlsDir := path.Join(uDir, common.DefaultConfigDirName, common.DefaultConfigBlsDirName)
	if _, err := os.Stat(hmyBlsDir); os.IsNotExist(err) {
		os.MkdirAll(hmyBlsDir, 0700)
	}
}

// LocalAccounts returns a slice of local account alias names
func LocalAccounts() []string {
	uDir, _ := homedir.Dir()
	files, _ := ioutil.ReadDir(path.Join(
		uDir,
		common.DefaultConfigDirName,
		common.DefaultConfigAccountAliasesDirName,
	))
	var accs []string
	for _, node := range files {
		if node.IsDir() {
			accs = append(accs, path.Base(node.Name()))
		}
	}
	return accs
}

// LocalBlsKeys returns a slice of encrypted BLS key filenames
func LocalBlsKeys() []string {
	uDir, _ := homedir.Dir()
	files, _ := ioutil.ReadDir(path.Join(
		uDir,
		common.DefaultConfigDirName,
		common.DefaultConfigBlsDirName,
	))
	var blsKeys []string
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".") {
			continue
		}
		blsKeys = append(blsKeys, path.Base(f.Name()))
	}
	return blsKeys
}

var (
	describeAddress       = fmt.Sprintf("%-24s\t\t%23s\n", "NAME", "ADDRESS")
	describeBls           = fmt.Sprintf("\nBLS KEYS (public)\n")
	NoUnlockBadPassphrase = errors.New("could not unlock account with passphrase, perhaps need different phrase")
)

func DescribeLocalAccounts() {
	fmt.Println(describeAddress)
	for _, name := range LocalAccounts() {
		ks := FromAccountName(name)
		allAccounts := ks.Accounts()
		for _, account := range allAccounts {
			fmt.Printf("%-48s\t%s\n", name, address.ToBech32(account.Address))
		}
	}
	fmt.Println(describeBls)
	for _, key := range LocalBlsKeys() {
		fmt.Printf(strings.TrimSuffix(key, ".key"))
	}
}

func DoesNamedAccountExist(name string) bool {
	for _, account := range LocalAccounts() {
		if account == name {
			return true
		}
	}
	return false
}

func FromAddress(bech32 string) *keystore.KeyStore {
	for _, name := range LocalAccounts() {
		ks := FromAccountName(name)
		allAccounts := ks.Accounts()
		for _, account := range allAccounts {
			if bech32 == address.ToBech32(account.Address) {
				return ks
			}
		}
	}
	return nil
}

func FromAccountName(name string) *keystore.KeyStore {
	uDir, _ := homedir.Dir()
	p := path.Join(uDir, c.DefaultConfigDirName, c.DefaultConfigAccountAliasesDirName, name)
	return common.KeyStoreForPath(p)
}

func DefaultAccountLocation() string {
	uDir, _ := homedir.Dir()
	return path.Join(uDir, c.DefaultConfigDirName, c.DefaultConfigAccountAliasesDirName)
}

func DefaultBlsLocation() string {
	uDir, _ := homedir.Dir()
	return path.Join(uDir, c.DefaultConfigDirName, c.DefaultConfigBlsDirName)
}

func UnlockedKeystore(from, unlockP string) (*keystore.KeyStore, *accounts.Account, error) {
	sender := address.Parse(from)
	ks := FromAddress(from)
	if ks == nil {
		return nil, nil, fmt.Errorf("could not open local keystore for %s", from)
	}
	account, lookupErr := ks.Find(accounts.Account{Address: sender})
	if lookupErr != nil {
		return nil, nil, fmt.Errorf("could not find %s in keystore", from)
	}
	if unlockError := ks.Unlock(account, unlockP); unlockError != nil {
		return nil, nil, errors.Wrap(NoUnlockBadPassphrase, unlockError.Error())
	}
	return ks, &account, nil
}
