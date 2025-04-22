package process

import (
	"strings"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/sirupsen/logrus"

	"github.com/saucer-man/wxdump/pkg/appver"
	"github.com/saucer-man/wxdump/pkg/model"
)

const (
	V3ProcessName = "WeChat"
	V4ProcessName = "Weixin"
	V3DBFile      = "Msg\\Misc.db"
	V4DBFile      = "db_storage\\message\\message_0.db"
)

// Detector 实现 Windows 平台的进程检测器
type WxDetector struct{}

// NewDetector 创建一个新的 Windows 检测器
func NewWxDetector() *WxDetector {
	return &WxDetector{}
}

// FindProcesses 查找所有微信进程并返回它们的信息
func (d *WxDetector) FindProcesses() ([]*model.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		logrus.Info("获取进程列表失败")
		return nil, err
	}

	var result []*model.Process
	for _, p := range processes {
		name, err := p.Name()
		name = strings.TrimSuffix(name, ".exe")
		if err != nil || (name != V3ProcessName && name != V4ProcessName) {
			continue
		}

		// v4 存在同名进程，需要继续判断 cmdline
		if name == V4ProcessName {
			cmdline, err := p.Cmdline()
			if err != nil {
				logrus.Info("获取进程命令行失败")
				continue
			}
			if strings.Contains(cmdline, "--") {
				continue
			}
		}

		// 获取进程信息
		procInfo, err := d.getProcessInfo(p)
		if err != nil {
			logrus.Infof("获取进程 %d 的信息失败", p.Pid)
			continue
		}

		result = append(result, procInfo)
	}

	return result, nil
}

// getProcessInfo 获取微信进程的详细信息
func (d *WxDetector) getProcessInfo(p *process.Process) (*model.Process, error) {
	procInfo := &model.Process{
		PID:    uint32(p.Pid),
		Status: model.StatusOffline,
	}

	// 获取可执行文件路径
	exePath, err := p.Exe()
	if err != nil {
		logrus.Info("获取可执行文件路径失败")
		return nil, err
	}
	procInfo.ExePath = exePath

	// 获取版本信息
	versionInfo, err := appver.New(exePath)
	if err != nil {
		logrus.Info("获取版本信息失败")
		return nil, err
	}
	procInfo.Version = versionInfo.Version
	procInfo.FullVersion = versionInfo.FullVersion

	// 初始化附加信息（数据目录、wxid名）
	if err := initializeProcessInfo(p, procInfo); err != nil {
		logrus.Info("初始化进程信息失败")
		// 即使初始化失败也返回部分信息
	}

	return procInfo, nil
}
