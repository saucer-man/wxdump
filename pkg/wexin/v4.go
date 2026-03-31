//go:build windows

package wexin

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MEM_COMMIT                = 0x1000
	PAGE_READONLY             = 0x02
	PAGE_READWRITE            = 0x04
	PAGE_EXECUTE_READ         = 0x20
	PAGE_EXECUTE_READWRITE    = 0x40
)

// 通用特征码：设备类型字符串
var devicePatterns = [][]byte{
	[]byte("android\x00"),
	[]byte("iphone\x00"),
	[]byte("ipad\x00"),
}

// 按顺序匹配：account、nickname、phone
var userBlockRe = regexp.MustCompile(
	`([\x20-\x7e]+)\x00+[\x00-\xff]{16}([\x20-\x7e]+)\x00+[\x00-\xff]{16}((?:\+?[1-9]\d{6,14})|(?:1[3-9]\d{9}))\x00`,
)

var phoneLikeRe = regexp.MustCompile(`(?:\+?[1-9]\d{6,14})|(?:1[3-9]\d{9})`)

type userInfo struct {
	Account  string
	Nickname string
	Phones   string
}

func extractPrintableASCII(base uintptr, b []byte, minLen int, maxCount int) []string {
	if minLen <= 0 {
		minLen = 1
	}
	if maxCount <= 0 {
		maxCount = 20
	}
	var out []string

	start := -1
	for i := 0; i <= len(b); i++ {
		isPrintable := false
		if i < len(b) {
			c := b[i]
			isPrintable = c >= 0x20 && c <= 0x7e
		}

		if isPrintable {
			if start == -1 {
				start = i
			}
			continue
		}

		if start != -1 {
			runLen := i - start
			if runLen >= minLen {
				addr := base + uintptr(start)
				s := string(b[start:i])
				out = append(out, fmt.Sprintf("0x%016X (+0x%X) len=%d %q", addr, start, runLen, s))
				if len(out) >= maxCount {
					return out
				}
			}
			start = -1
		}
	}
	return out
}

func readUserWindow(handle windows.Handle, deviceAddr uintptr) (uintptr, []byte, error) {
	start := deviceAddr - 0x280
	buf := make([]byte, 0x290)
	if err := windows.ReadProcessMemory(handle, start, &buf[0], uintptr(len(buf)), nil); err != nil {
		return 0, nil, err
	}
	return start, buf, nil
}

func parseUserBlock(handle windows.Handle, deviceAddr uintptr) *userInfo {
	_, buf, err := readUserWindow(handle, deviceAddr)
	if err != nil {
		return nil
	}
	loc := userBlockRe.FindSubmatch(buf)
	if loc == nil || len(loc) != 4 {
		return nil
	}
	account := strings.TrimSpace(string(loc[1]))
	nickname := strings.TrimSpace(string(loc[2]))
	phone := strings.TrimSpace(string(loc[3]))
	if account == "" || nickname == "" || phone == "" {
		return nil
	}
	if phone == account || phone == nickname {
		return nil
	}
	return &userInfo{Account: account, Nickname: nickname, Phones: phone}
}

func patternScanAll(handle windows.Handle, pattern []byte) []uintptr {
	var addrs []uintptr
	addr := uintptr(0)
	userLimit := uintptr(0x7FFFFFFF0000)
	// 从地址 0 开始，一直到 0x7FFFFFFF0000（64 位 Windows 用户空间上界），按区域遍历
	for addr < userLimit {
		// 用 VirtualQueryEx 查询当前地址所在内存区域的信息，包括：
		// BaseAddress：区域起始地址
		// RegionSize：区域大小
		// State：是否已提交（MEM_COMMIT）
		// Protect：保护属性（可读、可写、可执行等）
		var mbi windows.MemoryBasicInformation
		err := windows.VirtualQueryEx(handle, addr, &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			break
		}
		// 只处理满足以下条件的区域：
		// State == MEM_COMMIT：已提交
		// Protect 为可读（只读、读写、可执行读、可执行读写）
		// RegionSize > 0
		readable := mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE ||
			mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE
		if mbi.State == MEM_COMMIT && readable && mbi.RegionSize > 0 {
			// 读取当前区域内存，如果读取成功，则继续处理
			buf := make([]byte, mbi.RegionSize)
			err := windows.ReadProcessMemory(handle, mbi.BaseAddress, &buf[0], mbi.RegionSize, nil)
			if err == nil && uintptr(len(buf)) >= uintptr(len(pattern)) {
				// 在读取的内存中，查找特征码
				idx := 0
				for {
					i := bytes.Index(buf[idx:], pattern)
					if i < 0 {
						break
					}
					// 将找到的特征码地址添加到结果列表中
					addrs = append(addrs, mbi.BaseAddress+uintptr(idx+i))
					idx += i + 1
				}
			}
		}
		// 移动到下一个区域
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	// 返回找到的特征码地址列表
	return addrs
}

// 尝试从内存中找到手机号、账号等信息
// 内存布局：account账号、nickname昵称、手机号（按顺序）
func (a *Account) GetUserInfoV4() error {
	handle, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, uint32(a.PID))
	if err != nil {
		return fmt.Errorf("can't open process: %v", err)
	}
	defer windows.CloseHandle(handle)

	var addrs []uintptr
	var usedPat []byte
	for _, pat := range devicePatterns {
		addrs = patternScanAll(handle, pat)
		if len(addrs) > 0 {
			usedPat = pat
			logrus.Infof("[*] use pattern: %q\n", string(pat))
			break
		}
	}

	if len(addrs) == 0 {
		return fmt.Errorf("can't find pattern")
	}

	logrus.Infof("[*] pattern hit count=%d (pattern=%q)", len(addrs), string(usedPat))

	dumped := 0
	for _, addr := range addrs {
		info := parseUserBlock(handle, addr)
		if info == nil {
			if dumped < 30 {
				start, win, rerr := readUserWindow(handle, addr)
				if rerr != nil {
					logrus.Infof("[dump] deviceAddr=0x%016X read window failed: %v", addr, rerr)
				} else {
					// 额外打印窗口内是否出现了手机号样式，方便快速判断“数据变了”还是“正则不匹配”
					phoneLike := phoneLikeRe.FindIndex(win) != nil
					logrus.Infof("[dump] deviceAddr=0x%016X windowStart=0x%016X len=0x%X phoneLike=%v", addr, start, len(win), phoneLike)
					printables := extractPrintableASCII(start, win, 4, 60)
					if len(printables) == 0 {
						logrus.Infof("[dump] printable strings: (none)")
					} else {
						logrus.Infof("[dump] printable strings (minLen=4, max=60):\n%s", strings.Join(printables, "\n"))
					}
				}
				dumped++
			}
			continue
		}
		if info.Phones == "" {
			continue
		}
		a.WxAccount = info.Account
		a.Nickname = info.Nickname
		a.Phone = info.Phones
		logrus.Infof("get userinfo: account=%s nickname=%s phones=%s\n",
			a.WxAccount, a.Nickname, a.Phone)
		return nil
	}
	return fmt.Errorf("未解析到用户信息，可能是结构变化")
}

const (
	pageSz = 4096
	keySz  = 32
	saltSz = 16
	ivSz   = 16
	hmacSz = 64

	memCommit = 0x1000
	maxRegion = 500 * 1024 * 1024

	reserveSz = 80 // IV(16) + HMAC(64)
)

var readableProtect = map[uint32]struct{}{
	0x02: {}, 0x04: {}, 0x08: {}, 0x10: {}, 0x20: {}, 0x40: {}, 0x80: {},
}

var hexPattern = regexp.MustCompile(`x'([0-9a-fA-F]{64,192})'`)
var sqliteHeader = []byte("SQLite format 3\x00")

type dbFile struct {
	rel   string
	path  string
	sz    int64
	salt  string
	page1 []byte
}

// verifyEncKey 通过校验 DB 第 1 页的 HMAC，判断 encKey 是否正确。
func verifyEncKey(encKey, dbPage1 []byte) bool {
	if len(dbPage1) < pageSz {
		return false
	}
	salt := dbPage1[:saltSz]
	macSalt := make([]byte, saltSz)
	for i, b := range salt {
		macSalt[i] = b ^ 0x3A
	}
	macKey := pbkdf2.Key(encKey, macSalt, 2, keySz, sha512.New)
	hmacData := dbPage1[saltSz : pageSz-80+16]
	storedHmac := dbPage1[pageSz-64 : pageSz]
	hm := hmac.New(sha512.New, macKey)
	hm.Write(hmacData)
	_ = binary.Write(hm, binary.LittleEndian, uint32(1))
	return hmac.Equal(hm.Sum(nil), storedHmac)
}

func collectDBFiles(dbDir string) ([]dbFile, map[string][]string, error) {
	var list []dbFile
	saltToDBs := make(map[string][]string)
	var stack []string
	stack = append(stack, dbDir)
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		for _, ent := range entries {
			p := filepath.Join(dir, ent.Name())
			if ent.IsDir() {
				stack = append(stack, p)
				continue
			}

			name := ent.Name()
			if !strings.HasSuffix(name, ".db") || strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
				continue
			}

			info, err := ent.Info()
			if err != nil {
				return nil, nil, err
			}
			if info.Size() < pageSz {
				continue
			}

			f, err := os.Open(p)
			if err != nil {
				return nil, nil, err
			}
			page1 := make([]byte, pageSz)
			_, rerr := io.ReadFull(f, page1)
			_ = f.Close()
			if rerr != nil {
				continue
			}

			rel, err := filepath.Rel(dbDir, p)
			if err != nil {
				rel = p
			}
			rel = filepath.ToSlash(rel)
			salt := hex.EncodeToString(page1[:saltSz])
			list = append(list, dbFile{rel: rel, path: p, sz: info.Size(), salt: salt, page1: page1})
			saltToDBs[salt] = append(saltToDBs[salt], rel)
		}
	}
	return list, saltToDBs, nil
}

// decryptPageInto 解密单页（SQLCipher4 / WCDB），写入 out（4096 字节）。
// 注意：out 会被完全覆盖；pageData 必须是 4096 字节。
func decryptPageInto(block cipher.Block, pageData []byte, pgno int, out []byte) error {
	if len(pageData) != pageSz {
		return errors.New("page size mismatch")
	}
	if len(out) != pageSz {
		return errors.New("out page size mismatch")
	}
	ivOff := pageSz - reserveSz
	iv := pageData[ivOff : ivOff+ivSz]

	if pgno == 1 {
		// page1: salt(16) 明文保留，后面的 encrypted 才是 AES-CBC 密文
		encrypted := pageData[saltSz : pageSz-reserveSz]
		if len(encrypted)%aes.BlockSize != 0 {
			return errors.New("encrypted page1 not multiple of block size")
		}
		cbc := cipher.NewCBCDecrypter(block, iv)
		copy(out, pageData) // 先覆盖，避免残留
		copy(out[:len(sqliteHeader)], sqliteHeader)
		cbc.CryptBlocks(out[len(sqliteHeader):pageSz-reserveSz], encrypted)
		for i := pageSz - reserveSz; i < pageSz; i++ {
			out[i] = 0
		}
		return nil
	}

	encrypted := pageData[:pageSz-reserveSz]
	if len(encrypted)%aes.BlockSize != 0 {
		return errors.New("encrypted page not multiple of block size")
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(out[:pageSz-reserveSz], encrypted)
	for i := pageSz - reserveSz; i < pageSz; i++ {
		out[i] = 0
	}
	return nil
}

// decryptDatabase 解密整个 DB 文件到 outPath。
func decryptDatabase(dbPath, outPath string, encKey []byte) error {
	st, err := os.Stat(dbPath)
	if err != nil {
		return err
	}
	fileSize := st.Size()
	totalPages := int(fileSize / pageSz)
	if fileSize%pageSz != 0 {
		totalPages++
	}
	if totalPages <= 0 {
		return errors.New("empty db")
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}

	fin, err := os.Open(dbPath)
	if err != nil {
		return err
	}
	defer fin.Close()

	fout, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer fout.Close()

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}

	br := bufio.NewReaderSize(fin, 4<<20)
	bw := bufio.NewWriterSize(fout, 4<<20)
	defer bw.Flush()

	page := make([]byte, pageSz)
	outPage := make([]byte, pageSz)
	for pgno := 1; pgno <= totalPages; pgno++ {
		n, rerr := io.ReadFull(br, page)
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			if errors.Is(rerr, io.ErrUnexpectedEOF) {
				// 不足一页，尾部补 0
				for i := n; i < pageSz; i++ {
					page[i] = 0
				}
			} else {
				return rerr
			}
		}

		if err := decryptPageInto(block, page, pgno, outPage); err != nil {
			return err
		}
		if _, err := bw.Write(outPage); err != nil {
			return err
		}
	}
	return nil
}

func scanMemoryForKeys(data []byte, dbFiles []dbFile, saltToDBs map[string][]string,
	keyMap map[string]string, remainingSalts map[string]struct{}, baseAddr uint64, pid uint32,
) int {
	// 扫描进程内存中的 WCDB hex 缓存串（形如 x'...'），并用 DB 第 1 页 HMAC 验证后写入 keyMap。
	matches := 0
	for _, loc := range hexPattern.FindAllSubmatchIndex(data, -1) {
		if len(loc) < 4 {
			continue
		}
		hexStr := string(data[loc[2]:loc[3]])
		addr := baseAddr + uint64(loc[0])
		matches++
		hexLen := len(hexStr)

		if hexLen == 96 {
			encKeyHex := hexStr[:64]
			saltHex := hexStr[64:]
			if _, ok := remainingSalts[saltHex]; !ok {
				continue
			}
			encKey, err := hex.DecodeString(encKeyHex)
			if err != nil {
				continue
			}
			for _, df := range dbFiles {
				if df.salt == saltHex && verifyEncKey(encKey, df.page1) {
					keyMap[saltHex] = encKeyHex
					delete(remainingSalts, saltHex)
					logrus.Infof("[FOUND] salt=%s enc_key=%s pid=%d addr=0x%016X dbs=%s",
						saltHex, encKeyHex, pid, addr, strings.Join(saltToDBs[saltHex], ", "))
					break
				}
			}
		} else if hexLen == 64 {
			if len(remainingSalts) == 0 {
				continue
			}
			encKeyHex := hexStr
			encKey, err := hex.DecodeString(encKeyHex)
			if err != nil {
				continue
			}
			for _, df := range dbFiles {
				if _, ok := remainingSalts[df.salt]; !ok {
					continue
				}
				if verifyEncKey(encKey, df.page1) {
					saltHex := df.salt
					keyMap[saltHex] = encKeyHex
					delete(remainingSalts, saltHex)
					logrus.Infof("[FOUND] salt=%s enc_key=%s pid=%d addr=0x%016X dbs=%s",
						saltHex, encKeyHex, pid, addr, strings.Join(saltToDBs[saltHex], ", "))
					break
				}
			}
		} else if hexLen > 96 && hexLen%2 == 0 {
			encKeyHex := hexStr[:64]
			saltHex := hexStr[len(hexStr)-32:]
			if _, ok := remainingSalts[saltHex]; !ok {
				continue
			}
			encKey, err := hex.DecodeString(encKeyHex)
			if err != nil {
				continue
			}
			for _, df := range dbFiles {
				if df.salt == saltHex && verifyEncKey(encKey, df.page1) {
					keyMap[saltHex] = encKeyHex
					delete(remainingSalts, saltHex)
					logrus.Infof("[FOUND] salt=%s enc_key=%s pid=%d addr=0x%016X dbs=%s (long hex %d)",
						saltHex, encKeyHex, pid, addr, strings.Join(saltToDBs[saltHex], ", "), hexLen)
					break
				}
			}
		}
	}
	return matches
}

func crossVerifyKeys(dbFiles []dbFile, saltToDBs map[string][]string, keyMap map[string]string) {
	// 对尚未匹配的 salt，尝试用已知 key 逐个验证 DB 首页 HMAC，命中则复用该 key。
	missing := make(map[string]struct{})
	for s := range saltToDBs {
		if _, ok := keyMap[s]; !ok {
			missing[s] = struct{}{}
		}
	}
	if len(missing) == 0 || len(keyMap) == 0 {
		return
	}
	logrus.Infof("还有 %d 个 salt 未匹配，尝试交叉验证...", len(missing))
	for saltHex := range missing {
		for _, df := range dbFiles {
			if df.salt != saltHex {
				continue
			}
			for knownSalt, knownKeyHex := range keyMap {
				encKey, err := hex.DecodeString(knownKeyHex)
				if err != nil {
					continue
				}
				if verifyEncKey(encKey, df.page1) {
					keyMap[saltHex] = knownKeyHex
					logrus.Infof("[CROSS] salt=%s 可用 key from salt=%s", saltHex, knownSalt)
					delete(missing, saltHex)
				}
			}
			break
		}
	}
}

func buildKeyV4Result(dbFiles []dbFile, saltToDBs map[string][]string, keyMap map[string]string, dbDir string) map[string]interface{} {
	result := make(map[string]interface{})
	for _, df := range dbFiles {
		if enc, ok := keyMap[df.salt]; ok {
			result[df.rel] = map[string]interface{}{
				"enc_key": enc,
				"salt":    df.salt,
				"size_mb": math.Round(float64(df.sz)/1024/1024*10) / 10,
			}
		}
	}
	return result
}

func saveResults(dbFiles []dbFile, saltToDBs map[string][]string, keyMap map[string]string, dbDir, outFile string) error {
	logrus.Infof("结果: %d/%d salts 找到密钥", len(keyMap), len(saltToDBs))

	result := buildKeyV4Result(dbFiles, saltToDBs, keyMap, dbDir)
	for _, df := range dbFiles {
		if _, ok := keyMap[df.salt]; ok {
			logrus.Infof("OK: %s (%.1fMB)", df.rel, float64(df.sz)/1024/1024)
		} else {
			logrus.Infof("MISSING: %s (salt=%s)", df.rel, df.salt)
		}
	}

	if len(keyMap) == 0 {
		logrus.Infof("[!] 未提取到任何密钥，保留已有的 %s（如存在）", outFile)
		return errors.New("未能从任何微信进程中提取到密钥")
	}

	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		return err
	}
	logrus.Infof("密钥保存到: %s", outFile)

	var miss []string
	for _, df := range dbFiles {
		if _, ok := keyMap[df.salt]; !ok {
			miss = append(miss, df.rel)
		}
	}
	if len(miss) > 0 {
		logrus.Info("未找到密钥的数据库:")
		for _, rel := range miss {
			logrus.Infof("  %s", rel)
		}
	}
	return nil
}

type pidMem struct {
	pid   uint32
	memKb int
}

func getPids() ([]pidMem, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var pids []pidMem
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(name), "Weixin.exe") {
			continue
		}
		memInfo, err := p.MemoryInfo()
		if err != nil {
			pids = append(pids, pidMem{pid: uint32(p.Pid), memKb: 0})
			continue
		}
		pids = append(pids, pidMem{pid: uint32(p.Pid), memKb: int(memInfo.RSS / 1024)})
	}
	if len(pids) == 0 {
		return nil, errors.New("Weixin.exe 未运行")
	}
	for i := 0; i < len(pids); i++ {
		for j := i + 1; j < len(pids); j++ {
			if pids[j].memKb > pids[i].memKb {
				pids[i], pids[j] = pids[j], pids[i]
			}
		}
	}
	for _, p := range pids {
		logrus.Infof("[+] Weixin.exe PID=%d (%dMB)", p.pid, p.memKb/1024)
	}
	return pids, nil
}

func readMem(h windows.Handle, addr uint64, sz uint64) []byte {
	if sz == 0 || sz > maxRegion {
		return nil
	}
	buf := make([]byte, sz)
	var n uintptr
	err := windows.ReadProcessMemory(h, uintptr(addr), &buf[0], uintptr(sz), &n)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func enumRegions(h windows.Handle) []struct {
	base uint64
	sz   uint64
} {
	// 枚举可读、已提交的内存区域（过大区域会跳过），用于后续 ReadProcessMemory 扫描。
	var regs []struct {
		base uint64
		sz   uint64
	}
	var addr uintptr
	const maxUser = uintptr(0x7FFFFFFFFFFF)
	for addr < maxUser {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.State == memCommit {
			if _, ok := readableProtect[mbi.Protect]; ok {
				rs := uint64(mbi.RegionSize)
				if rs > 0 && rs < uint64(maxRegion) {
					regs = append(regs, struct {
						base uint64
						sz   uint64
					}{base: uint64(mbi.BaseAddress), sz: rs})
				}
			}
		}
		next := uint64(mbi.BaseAddress) + uint64(mbi.RegionSize)
		if next <= uint64(addr) {
			break
		}
		addr = uintptr(next)
	}
	return regs
}

func (a *Account) GetKeyV4() error {

	// 如果已经有密钥，直接返回
	if a.KeyV4 != nil {
		return nil
	}

	// 检查账号状态
	if a.Status != StatusOnline {
		return fmt.Errorf("WeChatAccountNotOnline")
	}

	dbDir := filepath.Join(a.DataDir, "db_storage")

	logrus.Info(strings.Repeat("=", 60))
	logrus.Info("  提取所有微信数据库密钥")
	logrus.Info(strings.Repeat("=", 60))

	dbFiles, saltToDBs, err := collectDBFiles(dbDir)
	if err != nil {
		return err
	}
	logrus.Infof("找到 %d 个数据库, %d 个不同的salt", len(dbFiles), len(saltToDBs))

	pidsX, err := getPids()
	if err != nil {
		return err
	}

	keyMap := make(map[string]string)
	remainingSalts := make(map[string]struct{})
	for s := range saltToDBs {
		remainingSalts[s] = struct{}{}
	}
	allHexMatches := 0
	t0 := time.Now()

	for _, pm := range pidsX {
		h, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pm.pid)
		if err != nil {
			logrus.Infof("[WARN] 无法打开进程 PID=%d，跳过", pm.pid)
			continue
		}

		regions := enumRegions(h)
		var totalBytes uint64
		for _, r := range regions {
			totalBytes += r.sz
		}
		totalMb := float64(totalBytes) / 1024 / 1024
		logrus.Infof("[*] 扫描 PID=%d (%.0fMB, %d 区域)", pm.pid, totalMb, len(regions))

		var scannedBytes uint64
		for regIdx, reg := range regions {
			data := readMem(h, reg.base, reg.sz)
			scannedBytes += reg.sz
			if len(data) > 0 {
				allHexMatches += scanMemoryForKeys(
					data, dbFiles, saltToDBs, keyMap, remainingSalts, reg.base, pm.pid,
				)
			}
			if (regIdx+1)%200 == 0 && totalBytes > 0 {
				elapsed := time.Since(t0).Seconds()
				progress := float64(scannedBytes) / float64(totalBytes) * 100
				logrus.Infof("  [%.1f%%] %d/%d salts matched, %d hex patterns, %.1fs",
					progress, len(keyMap), len(saltToDBs), allHexMatches, elapsed)
			}
		}
		_ = windows.CloseHandle(h)

		if len(remainingSalts) == 0 {
			logrus.Info("[+] 所有密钥已找到，跳过剩余进程")
			break
		}
	}

	elapsed := time.Since(t0).Seconds()
	logrus.Infof("扫描完成: %.1fs, %d 个进程, %d hex模式", elapsed, len(pidsX), allHexMatches)

	crossVerifyKeys(dbFiles, saltToDBs, keyMap)
	a.KeyV4 = buildKeyV4Result(dbFiles, saltToDBs, keyMap, dbDir)
	if len(keyMap) == 0 {
		return errors.New("未能从任何微信进程中提取到密钥")
	}
	return nil
}

func (a *Account) DecryptDBV4(decryptedDir string) error {
	if a == nil {
		return errors.New("account is nil")
	}
	if a.Version != 4 {
		return errors.New("not v4 account")
	}
	if a.DataDir == "" {
		return errors.New("DataDir is empty")
	}
	if decryptedDir == "" {
		return errors.New("decryptedDir is empty")
	}
	if a.KeyV4 == nil {
		return errors.New("KeyV4 is empty, call GetKeyV4() first or provide keys")
	}

	dbDir := filepath.Join(a.DataDir, "db_storage")
	dbFiles, saltToDBs, err := collectDBFiles(dbDir)
	if err != nil {
		return err
	}
	if len(dbFiles) == 0 || len(saltToDBs) == 0 {
		return errors.New("no db files found")
	}

	keyMap := make(map[string]string)
	for _, v := range a.KeyV4 {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		saltAny, okSalt := m["salt"]
		keyAny, okKey := m["enc_key"]
		if !okSalt || !okKey {
			continue
		}
		salt, okSalt := saltAny.(string)
		keyHex, okKey := keyAny.(string)
		if !okSalt || !okKey {
			continue
		}
		if salt == "" || keyHex == "" {
			continue
		}
		keyMap[salt] = keyHex
	}
	if len(keyMap) == 0 {
		return errors.New("KeyV4 does not contain any usable enc_key/salt")
	}

	outDir := filepath.Join(decryptedDir, a.Wxid)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	ok := 0
	skip := 0
	fail := 0

	for _, df := range dbFiles {
		keyHex, has := keyMap[df.salt]
		if !has {
			skip++
			continue
		}
		encKey, err := hex.DecodeString(keyHex)
		if err != nil || len(encKey) != keySz {
			fail++
			logrus.Infof("[DECRYPT] FAIL: %s (key decode)", df.rel)
			continue
		}

		outPath := filepath.Join(outDir, filepath.FromSlash(df.rel))
		logrus.Infof("[DECRYPT] %s", df.rel)
		if err := decryptDatabase(df.path, outPath, encKey); err != nil {
			fail++
			logrus.Infof("[DECRYPT] FAIL: %s (%v)", df.rel, err)
			continue
		}
		ok++
	}

	logrus.Infof("[DECRYPT] 完成: ok=%d skip=%d fail=%d 输出目录=%s", ok, skip, fail, outDir)
	return nil
}
