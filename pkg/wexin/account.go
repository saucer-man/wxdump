package wexin

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/saucer-man/wxdump/pkg/utils"

	"github.com/sirupsen/logrus"
)

const (
	StatusInit    = ""
	StatusOffline = "offline"
	StatusOnline  = "online"
)

const (
	V3ProcessName = "WeChat"
	V4ProcessName = "Weixin"
	V3DBFile      = "Msg\\Misc.db"
	V4DBFile      = "db_storage\\message\\message_0.db"
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
	ImageXorKey string
	ImageAesKey string
	PID         uint32
	ExePath     string
	Status      string
	ZipPath     string
}

// 微信4的目录名不是wxid，而是 wxid_xxxxx_786d == > wxid_xxxxx
func HandleWxidV4(wxid string) string {

	// 找到最后一个下划线的位置
	idx := strings.LastIndex(wxid, "_")
	if idx != -1 {
		wxid = wxid[:idx] // 截取到最后一个下划线之前
	}
	return wxid

}

// NewAccount 创建新的账号对象
func NewAccount(proc *utils.MyProcess) *Account {
	account := &Account{
		Version:     proc.Version,
		FullVersion: proc.FullVersion,
		PID:         proc.PID,
		ExePath:     proc.ExePath,
		Status:      StatusOffline,
	}

	// 初始化附加信息（DataDir、Wxid、Status）
	account.initializeProcessInfo(proc)
	return account
}

// initializeProcessInfo 获取进程的数据目录和账户名
func (a *Account) initializeProcessInfo(proc *utils.MyProcess) error {
	files, err := proc.P.OpenFiles()
	if err != nil {
		logrus.Infof("获取进程 %d 的打开文件失败", a.PID)
		return err
	}

	dbPath := V3DBFile
	if a.Version == 4 {
		dbPath = V4DBFile
	}

	for _, f := range files {
		if strings.HasSuffix(f.Path, dbPath) {
			filePath := f.Path[4:] // 移除 "\\?\" 前缀
			parts := strings.Split(filePath, string(filepath.Separator))
			if len(parts) < 4 {
				logrus.Info("无效的文件路径: " + filePath)
				continue
			}

			a.Status = StatusOnline
			if a.Version == 4 {
				a.DataDir = strings.Join(parts[:len(parts)-3], string(filepath.Separator))
				a.Wxid = HandleWxidV4(parts[len(parts)-4])
			} else {
				a.DataDir = strings.Join(parts[:len(parts)-2], string(filepath.Separator))
				a.Wxid = parts[len(parts)-3]
			}
			return nil
		}
	}

	return nil
}

// GetKey 获取账号的密钥
func (a *Account) GetUserInfo(ctx context.Context) error {
	// 如果已经有密钥，直接返回
	if a.Key != "" {
		return nil
	}

	// 检查账号状态
	if a.Status != StatusOnline {
		return fmt.Errorf("WeChatAccountNotOnline")
	}
	// 根据版本来创建一个验证器，主要就是看能不能正确解密
	//var err error
	////a.Validator, err = decrypt.NewValidator(a.Version, a.DataDir)
	//if err != nil {
	//	return err
	//}

	// 先获取userinfo
	if a.Version == 4 {
		logrus.Debug("version =4，接下来去获取xor key和aes key")
		a.GetImageXorKeyV4()
		a.GetImageAesKeyV4(context.Background())

	} else if a.Version == 3 {
		a.GetUserInfoV3(ctx) // V3版本直接使用偏移就行了，不用遍历内存了
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
	zipPath := filepath.Join(savePath, fmt.Sprintf("%s.zip", a.Wxid))
	zipFile, err := os.Create(zipPath)
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
	a.ZipPath = zipPath
	return nil
}
