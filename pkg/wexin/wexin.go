package wexin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/saucer-man/wxdump/pkg/utils"
)

func GetWeChatV3DirFromRegistry() (string, error) {
	// 打开注册表的微信路径: HKEY_CURRENT_USER\Software\Tencent\WeChat\FileSavePath
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Tencent\WeChat`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()
	//获取key的值
	value, _, err := key.GetStringValue("FileSavePath")
	if err != nil {
		return "", err
	}
	return value, nil

}

// 因为可能同时v3和v4都存在，所以就返回列表
func getWeChatDir() []string {
	var wechatRootDir []string
	wDir, err := GetWeChatV3DirFromRegistry()           // 一般来说4和3的exe不能共存，所以这里V3查到的话，就不用查KnownFolderPath了,v3没查到才会查KnownFolderPath
	logrus.Debug("GetWeChatV3DirFromRegistry err", err) // 这个一般都是MyDocument:
	if err != nil {
		// 下面尝试使用KnownFolderPath来获取用户document目录
		wDir, err = windows.KnownFolderPath(windows.FOLDERID_Documents, 0)
		if err != nil {
			fmt.Println("windows.KnownFolderPath error", err)
		}
	}

	if wDir == "MyDocument:" { // 如果wDir为MyDocument:，则将wDir变为实际的document目录
		// 获取%USERPROFILE%/Documents目录
		wDir, err = os.UserHomeDir()
		if err != nil {
			return wechatRootDir
		}
	}
	// 获取微信消息V3目录,判断目录是否存在
	wechatRootDirV3 := filepath.Join(wDir, "WeChat Files")

	if utils.Exists(wechatRootDirV3) {
		wechatRootDir = append(wechatRootDir, wechatRootDirV3)
	}
	// 判断v4最正常的目录是否存在,判断目录是否存在
	wechatRootDirV4 := filepath.Join(wDir, "xwechat_files")
	if utils.Exists(wechatRootDirV4) {
		wechatRootDir = append(wechatRootDir, wechatRootDirV4)
	}

	// 判断V4的第一种情况：C:\Users\xxx\xwechat_files目录是否存在
	homeDir, _ := os.UserHomeDir()
	if utils.Exists(filepath.Join(homeDir, "xwechat_files")) {
		wechatRootDir = append(wechatRootDir, filepath.Join(homeDir, "xwechat_files"))
	}

	// 判断V4的第二种情况: windows.FOLDERID_Documents的上一级
	if utils.Exists(filepath.Join(filepath.Dir(wDir), "xwechat_files")) {
		wechatRootDir = append(wechatRootDir, filepath.Join(homeDir, "xwechat_files"))
	}
	wechatRootDir = utils.Unique(wechatRootDir)
	return wechatRootDir
}

func GetWexinList() []*Account {
	var accounts []*Account

	// 获取微信的进程列表
	logrus.Info("try find to weixin processes")
	processes, _ := utils.FindWeixinProcesses()
	logrus.Infof("find weixin processes: %v", processes)
	for _, proc := range processes {
		// 将在线的进程转换为账号信息
		a := NewAccount(proc)
		logrus.Info("begin to handle pid:", a)

		err := a.GetUserInfo(context.Background()) // 扫描内存
		if err != nil {
			logrus.Info("account.GetUserInfo error:", err)
		}
		accounts = append(accounts, a)

	}
	logrus.Info("try find to weixin offlie directory")
	// 这里再读取一遍微信的目录，将离线的账号都也加到账号里面
	for _, weChatDir := range getWeChatDir() {
		logrus.Infof("try to read wechat dir:%s", weChatDir)
		// 获取微信消息目录下的所有用户目录
		files, err := os.ReadDir(weChatDir)
		if err != nil {
			logrus.Infof("os.ReadDir,weChatDir:%s, error: %+v", weChatDir, err)
			continue
		}
		for _, file := range files {
			// 排除All Users目录和Applet目录
			if file.Name() == "All Users" || file.Name() == "Applet" || file.Name() == "WMPF" {
				continue
			}
			var a *Account
			if utils.Exists(filepath.Join(weChatDir, file.Name(), "Msg", "Misc.db")) {
				// 判断wxid是否已经在进程里面了
				a = &Account{
					Wxid:    file.Name(),
					Version: 3,
					DataDir: filepath.Join(weChatDir, file.Name()),
					Status:  "offline",
				}

			} else if utils.Exists(filepath.Join(weChatDir, file.Name(), "db_storage", "message", "message_0.db")) {
				a = &Account{
					Wxid:    HandleWxidV4(file.Name()),
					Version: 4,
					DataDir: filepath.Join(weChatDir, file.Name()),
					Status:  "offline",
				}
			} else {
				continue
			}
			var isAlreadyProcess bool = false
			for _, acc := range accounts {
				if acc.Wxid == a.Wxid {
					isAlreadyProcess = true
				}
			}
			if !isAlreadyProcess {
				accounts = append(accounts, a)
			}

		}
	}

	return accounts
}
