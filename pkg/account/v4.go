// refer:https://github.com/saucer-man/wechat-dump-rs/blob/v4/docs/wechat_4_0_analysis.md

package account

import (
	"bytes"
	"fmt"
	"regexp"

	"encoding/binary"
	"encoding/hex"
	"runtime"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"context"
)

const (
	MEM_PRIVATE = 0x20000
)

func (a *Account) GetKeyV4(ctx context.Context) error {

	// 打开进程
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, a.PID)
	if err != nil {
		return fmt.Errorf("OpenProcess fail")
	}
	defer windows.CloseHandle(handle)

	// Create context to control all goroutines
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create channels for memory data and results
	memoryChannel := make(chan []byte, 100)
	resultChannel := make(chan string, 1)

	// Determine number of worker goroutines 2-8
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > MaxWorkers {
		workerCount = MaxWorkers
	}
	logrus.Debugf("Starting %d workers for V4 key search", workerCount)

	// Start consumer goroutines
	var workerWaitGroup sync.WaitGroup
	workerWaitGroup.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer workerWaitGroup.Done()
			a.workerV4(searchCtx, handle, memoryChannel, resultChannel)
		}()
	}

	// Start producer goroutine
	var producerWaitGroup sync.WaitGroup
	producerWaitGroup.Add(1)
	go func() {
		defer producerWaitGroup.Done()
		defer close(memoryChannel) // Close channel when producer is done
		err := a.findMemory(searchCtx, handle, memoryChannel)
		if err != nil {
			logrus.Debug("Failed to find memory regions")
		}
	}()

	// Wait for producer and consumers to complete
	go func() {
		producerWaitGroup.Wait()
		workerWaitGroup.Wait()
		close(resultChannel)
	}()

	// Wait for result
	select {
	case <-ctx.Done():
		return ctx.Err()
	case result, ok := <-resultChannel:
		if ok && result != "" {
			a.Key = result
			return nil
		}
	}
	logrus.Info("GetKeyV4 cant find correct key")
	return nil
}

// findMemoryV4 searches for writable memory regions for V4 version
// 扫描指定进程（handle）的内存，找到可读写（PAGE_READWRITE）并且是私有（MEM_PRIVATE）且比较大的内存区域，然后把读出来的内存数据发送到 memoryChannel。
func (a *Account) findMemory(ctx context.Context, handle windows.Handle, memoryChannel chan<- []byte) error {
	// Define search range
	minAddr := uintptr(0x10000)    // Process space usually starts from 0x10000
	maxAddr := uintptr(0x7FFFFFFF) // 32-bit process space limit

	if runtime.GOARCH == "amd64" {
		maxAddr = uintptr(0x7FFFFFFFFFFF) // 64-bit process space limit
	}
	logrus.Debugf("Scanning memory regions from 0x%X to 0x%X", minAddr, maxAddr)

	currentAddr := minAddr

	for currentAddr < maxAddr {
		var memInfo windows.MemoryBasicInformation
		err := windows.VirtualQueryEx(handle, currentAddr, &memInfo, unsafe.Sizeof(memInfo))
		if err != nil {
			break
		}

		// Skip small memory regions
		if memInfo.RegionSize < 1024*1024 {
			currentAddr += uintptr(memInfo.RegionSize)
			continue
		}

		// Check if memory region is readable and private
		if memInfo.State == windows.MEM_COMMIT && (memInfo.Protect&windows.PAGE_READWRITE) != 0 && memInfo.Type == MEM_PRIVATE {
			// Calculate region size, ensure it doesn't exceed limit
			regionSize := uintptr(memInfo.RegionSize)
			if currentAddr+regionSize > maxAddr {
				regionSize = maxAddr - currentAddr
			}

			// Read memory region
			memory := make([]byte, regionSize)
			if err = windows.ReadProcessMemory(handle, currentAddr, &memory[0], regionSize, nil); err == nil {
				select {
				case memoryChannel <- memory:
					logrus.Debugf("Memory region for analysis: 0x%X - 0x%X, size: %d bytes", currentAddr, currentAddr+regionSize, regionSize)
				case <-ctx.Done():
					return nil
				}
			}
		}

		// Move to next memory region
		currentAddr = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
	}

	return nil
}

// workerV4 processes memory regions to find V4 version key
// 从 memoryChannel 收到一块块内存数据，然后在每块内存里倒着搜特定的模式，找到疑似加密密钥的地址，再去读内存，验证这个地址是不是正确的密钥，如果是，就把它发送到 resultChannel
func (a *Account) workerV4(ctx context.Context, handle windows.Handle, memoryChannel <-chan []byte, resultChannel chan<- string) {
	// Define search pattern for V4

	// https://github.com/0xlane/wechat-dump-rs/blob/no-phone/wxdump/src/lib.rs
	keyPattern := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	ptrSize := 8
	littleEndianFunc := binary.LittleEndian.Uint64

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				return
			}

			index := len(memory)
			for {
				select {
				case <-ctx.Done():
					return // Exit if context cancelled
				default:
				}

				// Find pattern from end to beginning
				index = bytes.LastIndex(memory[:index], keyPattern)
				if index == -1 || index-ptrSize < 0 {
					break
				}

				// Extract and validate pointer value
				ptrValue := littleEndianFunc(memory[index-ptrSize : index])
				if ptrValue > 0x10000 && ptrValue < 0x7FFFFFFFFFFF {
					if key := a.validateKey(handle, ptrValue); key != "" {
						select {
						case resultChannel <- key:
							logrus.Debug("Valid key found: " + key)
							return
						default:
						}
					}
				}
				index -= 1 // Continue searching from previous position
			}
		}
	}
}

// validateKey validates a single key candidate
func (a *Account) validateKey(handle windows.Handle, addr uint64) string {
	keyData := make([]byte, 0x20) // 32-byte key
	if err := windows.ReadProcessMemory(handle, uintptr(addr), &keyData[0], uintptr(len(keyData)), nil); err != nil {
		return ""
	}

	// Validate key against database header
	if a.Validator.Validate(keyData) {
		return hex.EncodeToString(keyData)
	}

	return ""
}

func (a *Account) GetUserInfoV4(ctx context.Context) error {
	// 打开进程
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, a.PID)
	if err != nil {
		return fmt.Errorf("OpenProcess fail")
	}
	defer windows.CloseHandle(handle)

	// Create context to control all goroutines
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create channels for memory data and results
	memoryChannel := make(chan []byte, 100)
	resultChannel := make(chan []byte, 1)

	// Determine number of worker goroutines 2-8
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > MaxWorkers {
		workerCount = MaxWorkers
	}
	logrus.Debugf("Starting %d workers for V4 key search", workerCount)

	// Start consumer goroutines
	var workerWaitGroup sync.WaitGroup
	workerWaitGroup.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer workerWaitGroup.Done()
			a.workerInfoV4(searchCtx, handle, memoryChannel, resultChannel) // 这里启动workerCount个workerCount协程
		}()
	}

	// Start producer goroutine
	var producerWaitGroup sync.WaitGroup
	producerWaitGroup.Add(1)
	go func() {
		defer producerWaitGroup.Done()
		defer close(memoryChannel) // Close channel when producer is done
		err := a.findMemory(searchCtx, handle, memoryChannel)
		if err != nil {
			logrus.Debug("Failed to find memory regions")
		}
	}()

	// Wait for producer and consumers to complete
	go func() {
		producerWaitGroup.Wait()
		workerWaitGroup.Wait()
		close(resultChannel)
	}()

	// Wait for result
	select {
	case <-ctx.Done():
		return ctx.Err()
	case result, ok := <-resultChannel:
		if ok && result != nil {
			// 解析微信号（从字节 32 开始，直到遇到 \x00）
			wechatAccount := extractString(result, 32)

			// 解析昵称（从字节 64 开始，直到遇到 \x00）
			nickname := extractString(result, 64)

			// 解析手机号（从字节 96 开始，直到遇到 \x00）
			phone := extractString(result, 96)
			a.WxAccount = wechatAccount
			a.Nickname = nickname
			a.Phone = phone
			// 输出解析的字段
			logrus.Debugf("wechat account: %s\n", wechatAccount)
			logrus.Debugf("wechat nickname: %s\n", nickname)
			logrus.Debugf("wechat phone: %s\n", phone)
			return nil
		}
	}
	logrus.Info("ExtractUserInfo cant find correct memery by regex")
	return nil
}

// 从起始位置到找到的 \x00 位置之间的内容
func extractString(data []byte, start int) string {
	// 从指定起始位置开始查找 \x00 的位置
	end := bytes.IndexByte(data[start:], 0x00)
	if end == -1 {
		return "" // 如果没有找到，返回空字符串
	}
	// 提取从起始位置到找到的 \x00 位置之间的内容
	return string(data[start : start+end])
}

func (a *Account) workerInfoV4(ctx context.Context, handle windows.Handle, memoryChannel <-chan []byte, resultChannel chan<- []byte) {

	// 这里只能找国内的手机号，如果是国外手机号的话可以按链接的方法进行修改 https://github.com/0xlane/wechat-dump-rs/issues/26#issuecomment-2477940833
	pattern := `.{16}[\x00-\x20]\x00{7}(\x0f|\x1f)\x00{7}.{16}[\x00-\x20]\x00{7}(\x0f|\x1f)\x00{7}.{16}[\x01-\x20]\x00{7}(\x0f|\x1f)\x00{7}[0-9]{11}\x00{5}\x0b\x00{7}\x0f\x00{7}`

	// 美国或者香港手机号用下面这个
	// pattern = `.{16}[\x00-\x20]\x00{7}(\x0f|\x1f)\x00{7}.{16}[\x00-\x20]\x00{7}(\x0f|\x1f)\x00{7}.{16}[\x01-\x20]\x00{7}(\x0f|\x1f)\x00{7}[0-9+]{12}\x00{4}\x0c\x00{7}\x0f\x00{7}`

	// 编译正则
	re := regexp.MustCompile(pattern)

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				return
			}
			// Convert the memory data to a string (this may require further adjustments if non-text data)
			// strData := string(memory)

			// Use the regex to find matches in the memory data
			matches := re.FindSubmatch(memory)
			if len(matches) > 0 {
				logrus.Debug("Pattern matched in memory!")
				logrus.Debugf("Matched data: %x", matches[0])
				resultChannel <- matches[0] // 或做进一步解析再发送
			}
		}
	}
}
