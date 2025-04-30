package main

import (
	"encoding/json"
	"fmt"

	"github.com/saucer-man/wxdump/pkg/wexin"
	"github.com/sirupsen/logrus"
)

// GetAccounts 获取所有账号
func main() {
	logrus.SetLevel(logrus.DebugLevel)
	// 获取所有账号，并压缩到指定的地方
	accounts := wexin.GetWexinList()
	for _, account := range accounts {
		// 这里压缩微信数据
		logrus.Infof("try to zip account dir:%+v", account.DataDir)
		err := account.ZipWeChatUserData("D:\\", false)
		if err != nil {
			logrus.Infof("account.ZipWeChatUserData error:%+v", err)
		}
		bytes, _ := json.MarshalIndent(account, "", "  ")
		fmt.Println(string(bytes))
	}

	/*

		// 解密数据库，包括db文件、语音导出、图片解析
		var account = &account.Account{
			Key:     "xxxx",
			DataDir: "D:\\test\\wxid_xxxx",
			Version: 3,
		}
		export.ExportWeChatAllData(account, "D:\\test_report\\wxid_xxxx")
	*/
}
