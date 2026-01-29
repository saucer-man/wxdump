package utils

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func Is64Bit(handle windows.Handle) (bool, error) {
	var is32Bit bool
	if err := windows.IsWow64Process(handle, &is32Bit); err != nil {
		return false, fmt.Errorf("检查进程位数失败: %w", err)
	}
	return !is32Bit, nil
}

// 判断文件或者文件夹是否存在，这里并不区分文件夹还是文件，只要有一个存在就是存在
func Exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return os.IsExist(err)
	}
	return true
}

// 对列表去重
func Unique(elements []string) []string {
	encountered := map[string]struct{}{}
	result := []string{}

	for _, v := range elements {
		if _, ok := encountered[v]; !ok {
			encountered[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
