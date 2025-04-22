package wexin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/saucer-man/wxdump/pkg/account"
	"github.com/saucer-man/wxdump/pkg/process"
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
	// 判断目录是否存在,判断目录是否存在
	wechatRootDirV4 := filepath.Join(wDir, "xwechat_files")
	if utils.Exists(wechatRootDirV4) {
		wechatRootDir = append(wechatRootDir, wechatRootDirV4)
	}
	return wechatRootDir
}

func GetWexinList() []*account.Account {
	var accounts []*account.Account

	// 获取微信进程列表,将在线的进程转换为账号信息
	wxDetector := process.NewWxDetector()
	processes, _ := wxDetector.FindProcesses()

	for _, proc := range processes {

		a := account.NewAccount(proc)
		logrus.Debug("begin to handle pid:", a)

		err := a.GetUserInfo(context.Background())
		if err != nil {
			logrus.Info("account.GetUserInfo error:", err)
		}
		accounts = append(accounts, a)

	}
	// for _, account := range accounts {
	// 	bytes, _ := json.MarshalIndent(account, "", "  ")
	// 	fmt.Println(string(bytes))
	// }

	// 这里再读取一遍微信的目录，将离线的账号都也加到账号里面
	for _, weChatDir := range getWeChatDir() {
		logrus.Debugf("try to read wechat dir:%s", weChatDir)
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
			var a *account.Account
			if utils.Exists(filepath.Join(weChatDir, file.Name(), "Msg", "Misc.db")) {
				// 判断wxid是否已经在进程里面了
				a = &account.Account{
					Wxid:    file.Name(),
					Version: 3,
					DataDir: filepath.Join(weChatDir, file.Name()),
					Status:  "offline",
				}

			} else if utils.Exists(filepath.Join(weChatDir, file.Name(), "db_storage", "message", "message_0.db")) {
				a = &account.Account{
					Wxid:    process.HandleWxidV4(file.Name()),
					Version: 4,
					DataDir: filepath.Join(weChatDir, file.Name()),
					Status:  "offline",
				}
			} else {
				continue
			}
			var isAlreadyProcess bool = false
			for _, proc := range processes {
				if proc.Wxid == a.Wxid {
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
