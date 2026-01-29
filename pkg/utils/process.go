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
	logrus.Info("try to get wexin processes")
	processes, err := process.Processes()
	if err != nil {
		logrus.Info("get wexin processes err:", err)
		return nil, err
	}

	var result []*MyProcess
	for _, p := range processes {
		name, err := p.Name()
		name = strings.TrimSuffix(name, ".exe")
		if err != nil || (name != V3ProcessName && name != V4ProcessName) {
			continue
		}
		logrus.Infof("get wexin processes: %d", p.Pid)
		// v4 存在同名进程，需要继续判断 cmdline
		// 真正的微信进程是没有参数的，所以把--去掉
		if name == V4ProcessName {
			cmdline, err := p.Cmdline()
			if err != nil {
				logrus.Info("get wexin processes Cmdline err:", err)
				continue
			}
			if strings.Count(cmdline, "--") > 1 {
				logrus.Infof("get wexin processes cmdline: %s, pass", cmdline)
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
			logrus.Info("get wexin processes Exepath err:", err)
			continue
		}
		logrus.Infof("get wexin processes exePath: %s", exePath)
		procInfo.ExePath = exePath

		// 获取exe版本信息
		versionInfo, err := NewAppVer(exePath)
		if err != nil {
			logrus.Info("get get wexin processes version err:", err)
			continue
		}
		logrus.Infof("get wexin processes version: %d", versionInfo.Version)
		procInfo.Version = versionInfo.Version
		procInfo.FullVersion = versionInfo.FullVersion

		result = append(result, procInfo)
	}

	return result, nil
}
