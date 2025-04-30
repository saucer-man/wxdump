package process

import (
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/sirupsen/logrus"

	"github.com/saucer-man/wxdump/pkg/model"
)

// 微信4的目录名不是wxid，而是 wxid_xxxxx_786d == > wxid_xxxxx
func HandleWxidV4(wxid string) string {

	// 找到最后一个下划线的位置
	idx := strings.LastIndex(wxid, "_")
	if idx != -1 {
		wxid = wxid[:idx] // 截取到最后一个下划线之前
	}
	return wxid

}

// initializeProcessInfo 获取进程的数据目录和账户名
func initializeProcessInfo(p *process.Process, info *model.Process) error {
	files, err := p.OpenFiles()
	if err != nil {
		logrus.Infof("获取进程 %d 的打开文件失败", p.Pid)
		return err
	}

	dbPath := V3DBFile
	if info.Version == 4 {
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

			info.Status = model.StatusOnline
			if info.Version == 4 {
				info.DataDir = strings.Join(parts[:len(parts)-3], string(filepath.Separator))
				info.Wxid = HandleWxidV4(parts[len(parts)-4])
			} else {
				info.DataDir = strings.Join(parts[:len(parts)-2], string(filepath.Separator))
				info.Wxid = parts[len(parts)-3]
			}
			return nil
		}
	}

	return nil
}
