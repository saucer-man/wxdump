package utils

import (
	"strings"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/sirupsen/logrus"
)

type MyProcess struct {
	P           *process.Process
	PID         uint32
	ExePath     string
	Version     int
	FullVersion string
}

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

// FindWeixinProcesses 查找所有微信进程并返回它们的信息
func FindWeixinProcesses() ([]*MyProcess, error) {
	processes, err := process.Processes()
	if err != nil {
		logrus.Info("获取进程列表失败")
		return nil, err
	}

	var result []*MyProcess
	for _, p := range processes {
		name, err := p.Name()
		name = strings.TrimSuffix(name, ".exe")
		if err != nil || (name != V3ProcessName && name != V4ProcessName) {
			continue
		}

		// v4 存在同名进程，需要继续判断 cmdline
		// 真正的微信进程是没有参数的，所以把--去掉
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
		procInfo := &MyProcess{
			P:   p,
			PID: uint32(p.Pid),
		}
		// 获取exe可执行文件路径
		exePath, err := p.Exe()
		if err != nil {
			logrus.Infof("获取进程 %d 的可执行文件路径信息失败", p.Pid)
			continue
		}
		procInfo.ExePath = exePath

		// 获取exe版本信息
		versionInfo, err := NewAppVer(exePath)
		if err != nil {
			logrus.Infof("获取进程 %d 的版本信息失败", p.Pid)
			continue
		}
		procInfo.Version = versionInfo.Version
		procInfo.FullVersion = versionInfo.FullVersion

		result = append(result, procInfo)
	}

	return result, nil
}
