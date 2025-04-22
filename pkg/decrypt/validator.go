package decrypt

import (
	"path/filepath"
)

type Validator struct {
	version   int
	dbPath    string
	decryptor Decryptor
	dbFile    *DBFile
}

// NewValidator 创建一个仅用于验证的验证器
func NewValidator(version int, dataDir string) (*Validator, error) {
	dbFile := GetSimpleDBFile(version)
	dbPath := filepath.Join(dataDir + "/" + dbFile)
	return NewValidatorWithFile(version, dbPath)
}

func NewValidatorWithFile(version int, dbPath string) (*Validator, error) {
	decryptor, err := NewDecryptor(version)
	if err != nil {
		return nil, err
	}
	d, err := OpenDBFile(dbPath, decryptor.GetPageSize())
	if err != nil {
		return nil, err
	}

	return &Validator{

		version:   version,
		dbPath:    dbPath,
		decryptor: decryptor,
		dbFile:    d,
	}, nil
}

func (v *Validator) Validate(key []byte) bool {
	return v.decryptor.Validate(v.dbFile.FirstPage, key)
}

func GetSimpleDBFile(version int) string {
	switch {
	case version == 3:
		return "Msg\\Misc.db"
	case version == 4:
		return "db_storage\\message\\message_0.db"
	}
	return ""

}
