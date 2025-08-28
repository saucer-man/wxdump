package wexin

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"golang.org/x/sys/windows"
)

// Unmarshal the JSON into a map[string][]int
var OffSetMap map[string][]int

func init() {
	// https://raw.githubusercontent.com/xaoyaoo/PyWxDump/refs/heads/master/pywxdump/WX_OFFS.json
	offset := `
	{
		"3.2.1.154": [
		  328121948,
		  328122328,
		  328123056,
		  328121976,
		  328123020
		],
		"3.3.0.115": [
		  31323364,
		  31323744,
		  31324472,
		  31323392,
		  31324436
		],
		"3.3.0.84": [
		  31315212,
		  31315592,
		  31316320,
		  31315240,
		  31316284
		],
		"3.3.0.93": [
		  31323364,
		  31323744,
		  31324472,
		  31323392,
		  31324436
		],
		"3.3.5.34": [
		  30603028,
		  30603408,
		  30604120,
		  30603056,
		  30604100
		],
		"3.3.5.42": [
		  30603012,
		  30603392,
		  30604120,
		  30603040,
		  30604084
		],
		"3.3.5.46": [
		  30578372,
		  30578752,
		  30579480,
		  30578400,
		  30579444
		],
		"3.4.0.37": [
		  31608116,
		  31608496,
		  31609224,
		  31608144,
		  31609188
		],
		"3.4.0.38": [
		  31604044,
		  31604424,
		  31605152,
		  31604072,
		  31605116
		],
		"3.4.0.50": [
		  31688500,
		  31688880,
		  31689608,
		  31688528,
		  31689572
		],
		"3.4.0.54": [
		  31700852,
		  31701248,
		  31700920,
		  31700880,
		  31701924
		],
		"3.4.5.27": [
		  32133788,
		  32134168,
		  32134896,
		  32133816,
		  32134860
		],
		"3.4.5.45": [
		  32147012,
		  32147392,
		  32147064,
		  32147040,
		  32148084
		],
		"3.5.0.20": [
		  35494484,
		  35494864,
		  35494536,
		  35494512,
		  35495556
		],
		"3.5.0.29": [
		  35507980,
		  35508360,
		  35508032,
		  35508008,
		  35509052
		],
		"3.5.0.33": [
		  35512140,
		  35512520,
		  35512192,
		  35512168,
		  35513212
		],
		"3.5.0.39": [
		  35516236,
		  35516616,
		  35516288,
		  35516264,
		  35517308
		],
		"3.5.0.42": [
		  35512140,
		  35512520,
		  35512192,
		  35512168,
		  35513212
		],
		"3.5.0.44": [
		  35510836,
		  35511216,
		  35510896,
		  35510864,
		  35511908
		],
		"3.5.0.46": [
		  35506740,
		  35507120,
		  35506800,
		  35506768,
		  35507812
		],
		"3.6.0.18": [
		  35842996,
		  35843376,
		  35843048,
		  35843024,
		  35844068
		],
		"3.6.5.7": [
		  35864356,
		  35864736,
		  35864408,
		  35864384,
		  35865428
		],
		"3.6.5.16": [
		  35909428,
		  35909808,
		  35909480,
		  35909456,
		  35910500
		],
		"3.7.0.26": [
		  37105908,
		  37106288,
		  37105960,
		  37105936,
		  37106980
		],
		"3.7.0.29": [
		  37105908,
		  37106288,
		  37105960,
		  37105936,
		  37106980
		],
		"3.7.0.30": [
		  37118196,
		  37118576,
		  37118248,
		  37118224,
		  37119268
		],
		"3.7.5.11": [
		  37883280,
		  37884088,
		  37883136,
		  37883008,
		  37884052
		],
		"3.7.5.23": [
		  37895736,
		  37896544,
		  37895592,
		  37883008,
		  37896508
		],
		"3.7.5.27": [
		  37895736,
		  37896544,
		  37895592,
		  37895464,
		  37896508
		],
		"3.7.5.31": [
		  37903928,
		  37904736,
		  37903784,
		  37903656,
		  37904700
		],
		"3.7.6.24": [
		  38978840,
		  38979648,
		  38978696,
		  38978604,
		  38979612
		],
		"3.7.6.29": [
		  38986376,
		  38987184,
		  38986232,
		  38986104,
		  38987148
		],
		"3.7.6.44": [
		  39016520,
		  39017328,
		  39016376,
		  38986104,
		  39017292
		],
		"3.8.0.31": [
		  46064088,
		  46064912,
		  46063944,
		  38986104,
		  46064876
		],
		"3.8.0.33": [
		  46059992,
		  46060816,
		  46059848,
		  38986104,
		  46060780
		],
		"3.8.0.41": [
		  46064024,
		  46064848,
		  46063880,
		  38986104,
		  46064812
		],
		"3.8.1.26": [
		  46409448,
		  46410272,
		  46409304,
		  38986104,
		  46410236
		],
		"3.9.0.28": [
		  48418376,
		  48419280,
		  48418232,
		  38986104,
		  48419244
		],
		"3.9.2.23": [
		  50320784,
		  50321712,
		  50320640,
		  38986104,
		  50321676
		],
		"3.9.2.26": [
		  50329040,
		  50329968,
		  50328896,
		  38986104,
		  50329932
		],
		"3.9.5.81": [
		  61650872,
		  61652208,
		  61650680,
		  0,
		  61652144
		],
		"3.9.5.91": [
		  61654904,
		  61656240,
		  61654712,
		  38986104,
		  61656176
		],
		"3.9.6.19": [
		  61997688,
		  61997464,
		  61997496,
		  38986104,
		  61998960
		],
		"3.9.6.33": [
		  62030600,
		  62031936,
		  62030408,
		  0,
		  62031872
		],
		"3.9.7.15": [
		  63482696,
		  63484032,
		  63482504,
		  0,
		  63483968
		],
		"3.9.7.25": [
		  63482760,
		  63484096,
		  63482568,
		  0,
		  63484032
		],
		"3.9.7.29": [
		  63486984,
		  63488320,
		  63486792,
		  0,
		  63488256
		],
		"3.9.8.12": [
		  53479320,
		  53480288,
		  53479176,
		  0,
		  53480252
		],
		"3.9.8.15": [
		  64996632,
		  64997968,
		  64996440,
		  0,
		  64997904
		],
		"3.9.8.25": [
		  65000920,
		  65002256,
		  65000728,
		  0,
		  65002192
		],
		"3.9.9.27": [
		  68065304,
		  68066640,
		  68065112,
		  0,
		  68066576
		],
		"3.9.9.35": [
		  68065304,
		  68066640,
		  68065112,
		  0,
		  68066576
		],
		"3.9.9.43": [
		  68065944,
		  68067280,
		  68065752,
		  0,
		  68067216
		],
		"3.9.10.19": [
		  95129768,
		  95131104,
		  95129576,
		  0,
		  95131040
		],
		"3.9.10.27": [
		  95125656,
		  95126992,
		  95125464,
		  0,
		  95126928
		],
		"3.9.11.17": [
		  93550360,
		  93551696,
		  93550168,
		  0,
		  93551632
		],
		"3.9.11.19": [
		  93550296,
		  93551632,
		  93550104,
		  0,
		  93551568
		],
		"3.9.11.23": [
		  93701208,
		  93700984,
		  93701016,
		  0,
		  93700920
		],
		"3.9.11.25": [
		  93701080,
		  93702416,
		  93700888,
		  0,
		  93702352
		],
		"3.9.12.15": [
		  93813544,
		  93814880,
		  93813352,
		  0,
		  93814816
		],
		"3.9.12.17": [
		  93834984,
		  93836320,
		  93834792,
		  0,
		  93836256
		],
		"3.9.12.31": [
		  94516904,
		  94518240,
		  94516712,
		  0,
		  94518176
		],
		"3.9.12.37": [
		  94520808,
		  94522144,
		  94522146,
		  0,
		  94522080
		],
		"3.9.12.45": [
		  94503784,
		  94505120,
		  94503592,
		  0,
		  94505056
		],
		"3.9.12.51": [
		  94555176,
		  94556512,
		  94554984,
		  0,
		  94556448
		],
		"3.9.12.55": [
		  94550988,
		  94552544,
		  94551016,
		  0,
		  94552480
		]
	  }`

	json.Unmarshal([]byte(offset), &OffSetMap)

}

const (
	V3ModuleName = "WeChatWin.dll"
)

func (a *Account) GetUserInfoV3(ctx context.Context) error {
	// 首先判断版本号是否已经收集
	if _, ok := OffSetMap[a.FullVersion]; !ok {
		logrus.Info("version no support to get userinfo")
		return nil
	}
	// Find WeChatWin.dll module
	weChatWinDllModel, isFound := FindModule(a.PID, V3ModuleName)
	if !isFound {
		return fmt.Errorf("FindModule cant find WeChatWin.dll")
	}
	logrus.Debug("Found WeChatWin.dll module at base address: 0x" + fmt.Sprintf("%X", weChatWinDllModel.ModBaseAddr))

	// Open WeChat process
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, a.PID)
	if err != nil {
		return fmt.Errorf("OpenProcess fail")
	}
	defer windows.CloseHandle(handle)
	// 获取微信昵称
	nickName, err := GetWeChatData(handle, weChatWinDllModel.ModBaseAddr+uintptr(OffSetMap[a.FullVersion][0]), 100)

	if err != nil {
		logrus.Info("get nickname error: ", err)
		return err
	}
	a.Nickname = nickName
	logrus.Infof("get nickname:%+v\n", nickName)
	// 获取微信账号
	account, err := GetWeChatData(handle, weChatWinDllModel.ModBaseAddr+uintptr(OffSetMap[a.FullVersion][1]), 100)
	if err != nil {
		logrus.Info("get account error: ", err)
		return nil

	}

	a.WxAccount = account
	logrus.Infof("get account:%+v\n", account)
	// 获取微信手机号
	phone, err := GetWeChatData(handle, weChatWinDllModel.ModBaseAddr+uintptr(OffSetMap[a.FullVersion][2]), 100)
	if err != nil {
		logrus.Info("get mobile error: ", err)
		return err
	}

	a.Phone = phone
	logrus.Infof("get phone:%+v\n", phone)
	// 获取微信密钥
	keyBytes, err := GetWeChatKey(handle, weChatWinDllModel.ModBaseAddr+uintptr(OffSetMap[a.FullVersion][4]), 8)

	if err != nil {
		logrus.Info("get key error: ", err)
		return err
	}

	a.Key = strings.ToUpper(hex.EncodeToString(keyBytes))
	logrus.Infof("get key:%+v\n", a.Key)
	return nil
}

// 从指定内存位置，读取key
func GetWeChatKey(processHandler windows.Handle, address uintptr, addressLen int) ([]byte, error) {
	array := make([]byte, addressLen)

	// 从指定地址读取内存
	err := windows.ReadProcessMemory(processHandler, address, &array[0], uintptr(addressLen), nil)
	if err != nil {
		// fmt.Printf("读取内存失败: %v\n", err)
		return nil, err
	}

	// 逆序转换为 int 地址（密钥地址）
	keyAddress := uintptr(binary.LittleEndian.Uint64(array))

	// 读取密钥
	key := make([]byte, 32)

	err = windows.ReadProcessMemory(processHandler, keyAddress, &key[0], uintptr(len(key)), nil)
	if err != nil {
		// fmt.Printf("读取密钥失败: %v\n", err)
		return nil, err
	}
	// // 将byte数组转成hex字符串，并转成大写
	// key1 := hex.EncodeToString(key)
	// key1 = strings.ToUpper(key1)
	return key, nil
}

// 获取微信内存offset偏移的数据
func GetWeChatData(process windows.Handle, offset uintptr, nSize int) (string, error) {
	var buffer = make([]byte, nSize)
	err := windows.ReadProcessMemory(process, offset, &buffer[0], uintptr(nSize), nil)
	if err != nil {
		return "", err
	}
	// 声明一个字节数组，暂时为空
	var textBytes []byte = nil
	for _, v := range buffer {
		if v == 0 {
			break
		}
		textBytes = append(textBytes, v)
	}
	// 返回utf8编码的字符串
	return string(textBytes), nil
}

// FindModule searches for a specified module in the process
func FindModule(pid uint32, name string) (module windows.ModuleEntry32, isFound bool) {
	// Create module snapshot
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		logrus.Debugf("Failed to create module snapshot for PID %d: %v", pid, err)
		return module, false
	}
	defer windows.CloseHandle(snapshot)

	// Initialize module entry structure
	module.Size = uint32(windows.SizeofModuleEntry32)

	// Get the first module
	if err := windows.Module32First(snapshot, &module); err != nil {
		logrus.Debugf("Module32First failed for PID %d: %v", pid, err)
		return module, false
	}

	// Iterate through all modules to find WeChatWin.dll
	for ; err == nil; err = windows.Module32Next(snapshot, &module) {
		if windows.UTF16ToString(module.Module[:]) == name {
			return module, true
		}
	}
	return module, false
}
