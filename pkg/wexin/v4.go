// refer:https://github.com/saucer-man/wechat-dump-rs/blob/v4/docs/wechat_4_0_analysis.md

package wexin

import (
	"bytes"
	"context"
	"crypto/aes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"encoding/binary"
	"encoding/hex"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	MEM_PRIVATE = 0x20000
)

// Format defines the header and extension for different image types
type Format struct {
	Header []byte
	AesKey []byte
	Ext    string
}

var (
	// Common image format definitions
	JPG     = Format{Header: []byte{0xFF, 0xD8, 0xFF}, Ext: "jpg"}
	PNG     = Format{Header: []byte{0x89, 0x50, 0x4E, 0x47}, Ext: "png"}
	GIF     = Format{Header: []byte{0x47, 0x49, 0x46, 0x38}, Ext: "gif"}
	TIFF    = Format{Header: []byte{0x49, 0x49, 0x2A, 0x00}, Ext: "tiff"}
	BMP     = Format{Header: []byte{0x42, 0x4D}, Ext: "bmp"}
	WXGF    = Format{Header: []byte{0x77, 0x78, 0x67, 0x66}, Ext: "wxgf"}
	Formats = []Format{JPG, PNG, GIF, TIFF, BMP, WXGF}

	V4Format1 = Format{Header: []byte{0x07, 0x08, 0x56, 0x31}, AesKey: []byte("cfcd208495d565ef")}
	V4Format2 = Format{Header: []byte{0x07, 0x08, 0x56, 0x32}, AesKey: []byte("0000000000000000")} // FIXME
	V4Formats = []*Format{&V4Format1, &V4Format2}

	// WeChat v4 related constants
	V4XorKey byte = 0x37               // Default XOR key for WeChat v4 dat files
	JpgTail       = []byte{0xFF, 0xD9} // JPG file tail marker

	aesKeyRegex = regexp.MustCompile(`[a-z0-9]{16}`) // 全局预编译正则
)

// GetImageXorKey scans a directory for "_t.dat" files to calculate and set
// the global XOR key for WeChat v4 dat files
// Returns the found key and any error encountered
func (a *Account) GetImageXorKeyV4() {
	// Walk the directory recursively
	err := filepath.Walk(a.DataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process "_t.dat" files (thumbnail files)
		if !strings.HasSuffix(info.Name(), "_t.dat") {
			return nil
		}

		// Read file content
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Check if it's a WeChat v4 dat file
		if len(data) < 6 || (!bytes.Equal(data[:4], V4Format1.Header) && !bytes.Equal(data[:4], V4Format2.Header)) {
			return nil
		}

		// Parse file header
		if len(data) < 15 {
			return nil
		}

		// Get XOR encryption length
		xorEncryptLen := binary.LittleEndian.Uint32(data[10:14])

		// Get data after header
		fileData := data[15:]

		// Skip if there's no XOR-encrypted part
		if xorEncryptLen == 0 || uint32(len(fileData)) <= uint32(len(fileData))-xorEncryptLen {
			return nil
		}

		// Get XOR-encrypted part
		xorData := fileData[uint32(len(fileData))-xorEncryptLen:]

		// Calculate XOR key
		key, err := calculateXorKeyV4(xorData)
		if err != nil {
			return nil
		}

		// Set global XOR key
		a.ImageXorKey = fmt.Sprintf("0X%02X", key)
		logrus.Infof("get xor key: %s", a.ImageXorKey)
		// Stop traversal after finding a valid key
		return filepath.SkipAll
	})

	if err != nil && err != filepath.SkipAll {
		logrus.Infof("error scanning directory: %v", err)
	}

}

// calculateXorKeyV4 calculates the XOR key for WeChat v4 dat files
// by analyzing the file tail against known JPG ending bytes (FF D9)
func calculateXorKeyV4(data []byte) (byte, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("data too short to calculate XOR key")
	}

	// Get the last two bytes of the file 获取最后两个字节
	fileTail := data[len(data)-2:]

	// Assuming it's a JPG file, the tail should be FF D9，和FF D9进行异或
	xorKeys := make([]byte, 2)
	for i := 0; i < 2; i++ {
		xorKeys[i] = fileTail[i] ^ JpgTail[i]
	}

	// Verify that both bytes yield the same XOR key
	if xorKeys[0] == xorKeys[1] {
		return xorKeys[0], nil
	}

	// If inconsistent, return the first byte as key with a warning
	return xorKeys[0], fmt.Errorf("inconsistent XOR key, using first byte: 0x%x", xorKeys[0])
}

func (a *Account) GetImageAesKeyV4(ctx context.Context) error {
	// 首先从目录下获取一个aes解密后的.dat文件，获取EncryptedData
	// Walk the directory to find *.dat files (excluding *_t.dat files)
	EncryptedData := make([]byte, aes.BlockSize)
	filepath.Walk(filepath.Join(a.DataDir, "msg", "attach"), func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process *.dat files but exclude *_t.dat files
		if !strings.HasSuffix(info.Name(), ".dat") || strings.HasSuffix(info.Name(), "_t.dat") {
			return nil
		}

		// Read file content
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil
		}

		// Check if header matches V4Format2.Header
		// Get aes.BlockSize (16) bytes starting from position 15
		if len(data) >= 15+aes.BlockSize && bytes.Equal(data[:4], V4Format2.Header) {
			logrus.Debugf("get aes verify filePath:%s", filePath)
			copy(EncryptedData, data[15:15+aes.BlockSize])
			return filepath.SkipAll // Found what we need, stop walking
		}

		return nil
	})
	// EncryptedData, _ = hex.DecodeString("a64a9398b283d8cb")
	// 方法1：打印为十六进制字符串
	logrus.Debug("EncryptedData Hex:", hex.EncodeToString(EncryptedData))
	// Open process handle
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

	// Determine number of worker goroutines
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > 4 {
		workerCount = 4
	}
	logrus.Debugf("Starting %d workers for V4 Image Aes key search", workerCount)

	// Start consumer goroutines
	//消费者，并发消费数据，使用workerWaitGroup进行控制
	var workerWaitGroup sync.WaitGroup
	workerWaitGroup.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer workerWaitGroup.Done()
			a.workerV4(searchCtx, handle, memoryChannel, resultChannel, EncryptedData)
		}()
	}

	// Start producer goroutine
	//生产者程序，开一个就够了，使用producerWaitGroup进行等待
	var producerWaitGroup sync.WaitGroup
	producerWaitGroup.Add(1)
	go func() {
		defer producerWaitGroup.Done()
		defer close(memoryChannel) // 生产结束后，关闭memoryChannel
		err := a.findMemory(searchCtx, handle, memoryChannel)
		if err != nil {
			logrus.Debug("Failed to find memory regions")
		}
	}()

	// Wait for producer and consumers to complete
	// 等待生产者和消费者都结束后，就关闭resultChannel
	go func() {
		producerWaitGroup.Wait()
		workerWaitGroup.Wait()
		close(resultChannel)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-resultChannel:
			if !ok {
				// Channel closed, all workers finished, return whatever keys we found
				logrus.Info("no valid image aes key")
				return fmt.Errorf("no valid image aes key")
			}

			// Update our best found keys

			a.ImageAesKey = result
			// If we have both keys, we can return early
			if a.ImageAesKey != "" {
				// 这里cancel有啥用，难道有不cancel的情况？
				cancel() // Cancel remaining work
				return nil
			}
		}
	}
}

// findMemoryV4 searches for writable memory regions for V4 version
// 生产者，这个是通用的，遍历内存，然后将data发送给memoryChannel
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
		if memInfo.RegionSize < 16*1024 {
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
					// logrus.Debugf("Memory region for analysis: 0x%X - 0x%X, size: %d bytes", currentAddr, currentAddr+regionSize, regionSize)
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
// 消费者，消费findMemory生产的数据，然后将结果发送给resultChannel
func (a *Account) workerV4(ctx context.Context, handle windows.Handle, memoryChannel <-chan []byte, resultChannel chan<- string, EncryptedData []byte) {

	// ptrSize := 8
	// littleEndianFunc := binary.LittleEndian.Uint64

	// keysFound := make(map[uint64]bool) // Track processed addresses to avoid duplicates

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				return
			}

			matches := aesKeyRegex.FindAll(memory, -1)
			for _, match := range matches {
				// match 就是 []byte，长度应该是 16
				// keyData = []byte("a64a9398b283d8cb")
				// logrus.Debugf(string(keyData))
				// Validate key and determine type
				if ValidateImageAesKeyV4(EncryptedData, match) {
					// logrus.Warn("找到了！！！！")
					result := string(match)
					select {
					case resultChannel <- result:
					default:
					}
					return
				}
			}
			/*
				for i := 0; i <= len(memory)-16; i++ {
					keyCandidate := memory[i : i+16]
					if ValidateImageAesKeyV4(EncryptedData, keyCandidate) {
						logrus.Warnf("找到 AES key: %s", string(keyCandidate))
						select {
						case resultChannel <- string(keyCandidate):
						default:
						}
						return
					}
				}*/

		}
	}
}

// validateKey validates a single key candidate and returns the key and whether it's an image key
func (a *Account) validateKey(handle windows.Handle, EncryptedData []byte, addr uint64) (string, bool) {
	keyData := make([]byte, 0x20) // 32-byte key
	if err := windows.ReadProcessMemory(handle, uintptr(addr), &keyData[0], uintptr(len(keyData)), nil); err != nil {
		return "", false
	}

	//  check if it's a valid image key
	if ValidateImageAesKeyV4(EncryptedData, keyData) {
		return hex.EncodeToString(keyData[:16]), true // Image key
	}

	return "", false
}

// 判断key是否是aes key，解密EncryptedData后，开头是JPG或者WXGF即可
func ValidateImageAesKeyV4(EncryptedData, key []byte) bool {
	if len(key) < 16 {
		return false
	}
	aesKey := key[:16]

	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return false
	}

	decrypted := make([]byte, len(EncryptedData))
	cipher.Decrypt(decrypted, EncryptedData)

	return bytes.HasPrefix(decrypted, JPG.Header) || bytes.HasPrefix(decrypted, WXGF.Header)
}
