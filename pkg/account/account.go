package account

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/saucer-man/wxdump/pkg/decrypt"
	"github.com/saucer-man/wxdump/pkg/model"
	"github.com/sirupsen/logrus"
)

// Account 表示一个微信账号
type Account struct {
	Wxid        string
	WxAccount   string
	Nickname    string
	Phone       string
	Version     int
	FullVersion string
	DataDir     string
	Key         string
	PID         uint32
	ExePath     string
	Status      string
	Validator   *decrypt.Validator
}

// NewAccount 创建新的账号对象
func NewAccount(proc *model.Process) *Account {
	return &Account{
		Wxid:        proc.Wxid,
		Version:     proc.Version,
		FullVersion: proc.FullVersion,
		DataDir:     proc.DataDir,
		PID:         proc.PID,
		ExePath:     proc.ExePath,
		Status:      proc.Status,
	}
}

// GetKey 获取账号的密钥
func (a *Account) GetUserInfo(ctx context.Context) error {
	// 如果已经有密钥，直接返回
	if a.Key != "" {
		return nil
	}

	// 检查账号状态
	if a.Status != model.StatusOnline {
		return fmt.Errorf("WeChatAccountNotOnline")
	}
	// 根据版本来创建一个验证器，主要就是看能不能正确解密
	var err error
	a.Validator, err = decrypt.NewValidator(a.Version, a.DataDir)
	if err != nil {
		return err
	}

	// 先获取userinfo
	if a.Version == 4 {
		err = a.GetUserInfoV4(ctx)
		if err != nil {
			return err
		}
		// if a.Key == "" {
		// 	err = a.GetKeyV4(ctx)
		// 	if err != nil {
		// 		return err
		// 	}
		// }
	} else if a.Version == 3 {
		a.GetUserInfoV3(ctx)
		if a.Key == "" {
			a.GetKeyV3(ctx)
		}
	}
	return nil
}

// ZipWeChatUserData 压缩微信用户数据
func (a *Account) ZipWeChatUserData(savePath string, isSure bool) error {
	// 如果不确定，检查数据库修改时间
	if !isSure {
		var dbPath string
		// 根据微信版本决定数据库路径
		if a.Version == 4 {
			// 版本4的数据库路径
			dbPath = filepath.Join(a.DataDir, "db_storage", "session", "session.db")
		} else {
			// v3版本的数据库路径
			dbPath = filepath.Join(a.DataDir, "Msg", "MicroMsg.db")
		}

		// 获取数据库文件信息
		fileInfo, err := os.Stat(dbPath)
		if err != nil {
			// 获取文件信息失败时返回错误
			return fmt.Errorf("failed to get database info: %v", err)
		}

		// 获取文件最后修改时间
		modTime := fileInfo.ModTime()
		// 计算距离当前时间的天数差
		daysDiff := time.Since(modTime).Hours() / 24
		logrus.Debugf("db daysDiff:%.1f days", daysDiff)

		if daysDiff > 30 {
			// 如果超过30天，返回错误
			logrus.Infof("database file is too old (%.1f days)", daysDiff)
			return nil
		}

	}
	// 创建zip文件
	zipFile, err := os.Create(filepath.Join(savePath, fmt.Sprintf("%s.zip", a.Wxid)))
	if err != nil {
		return fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Determine which subdirectory to traverse based on version
	var targetDir string
	if a.Version == 4 {
		targetDir = filepath.Join(a.DataDir, "db_storage")
	} else {
		targetDir = filepath.Join(a.DataDir, "Msg")
	}

	// Walk through the appropriate directory
	err = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Only process .db files
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".db") {
			logrus.Debugf("Zipping file: %s", path)
			// Open file

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			// Get relative path by subtracting a.DataDir from path's absolute path
			relPath, err := filepath.Rel(targetDir, path)
			if err != nil {
				return err
			}
			zipEntry, err := zipWriter.Create(relPath)
			if err != nil {
				return err
			}

			// Copy file content to zip
			_, err = io.Copy(zipEntry, file)
			return err
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %v", err)
	}
	logrus.Infof("Successful zipped WeChat user data for %s to %s", a.Wxid, zipFile.Name())
	return nil
}
