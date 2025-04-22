package export

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/git-jiadong/go-lame"
	"github.com/git-jiadong/go-silk"
	_ "github.com/mattn/go-sqlite3"
	"github.com/saucer-man/wxdump/pkg/account"
	"github.com/saucer-man/wxdump/pkg/decrypt"
	"github.com/saucer-man/wxdump/pkg/utils"
	"github.com/sirupsen/logrus"
)

func ExportWeChatAllData(a *account.Account, outPath string) error {

	err := exportWeChatDateBase(a, outPath)
	if err != nil {
		logrus.Info("exportWeChatDateBase error:", err)
		return err
	}

	err = exportWeChatBat(a, outPath)
	if err != nil {
		logrus.Info("exportWeChatBat error:", err)
		return err
	}
	err = exportWeChatVideoAndFile(a, outPath)
	if err != nil {
		logrus.Info("exportWeChatVideoAndFile error:", err)
		return err
	}
	err = exportWeChatVoice(outPath)
	if err != nil {
		logrus.Info("exportWeChatVoice error:", err)
		return err
	}
	err = exportWeChatHeadImage(outPath)
	if err != nil {
		logrus.Info("exportWeChatHeadImage error:", err)
	}
	return nil
}

func exportWeChatDateBase(a *account.Account, outDir string) error {
	// 创建解析函数
	decryptor, err := decrypt.NewDecryptor(a.Version)
	if err != nil {
		return err
	}
	// 遍历dbDir文件夹下面的db文件
	dbDir := filepath.Join(a.DataDir, "Msg")
	if a.Version == 4 {
		dbDir = filepath.Join(a.DataDir, "db_storage")
	}

	err = filepath.Walk(dbDir, func(path string, finfo os.FileInfo, err error) error {
		if err != nil {
			logrus.Printf("filepath.Walk：%v\n", err)
			return err
		}
		if !finfo.IsDir() && strings.HasSuffix(path, ".db") {
			relPath, err := filepath.Rel(a.DataDir, path)
			if err != nil {
				logrus.Infof("filepath.Rel %s to %s error:%v", a.DataDir, path, err)
				return err
			}
			outFilePath := filepath.Join(outDir, relPath)
			if utils.Exists(outFilePath) {
				logrus.Infof("exportWeChatDateBase %s already exists", outFilePath)
				return nil
			}
			err = os.MkdirAll(filepath.Dir(outFilePath), 0755)
			if err != nil {
				logrus.Infof("MkdirAll %s error:%v", filepath.Dir(outFilePath), err)
				return err
			}
			logrus.Debugf("decrypting db %s", path)
			// 解密该db,保存在outFilePath
			err = decryptor.Decrypt(context.Background(), path, a.Key, outFilePath)
			if err != nil {
				if err.Error() == "database file is already decrypted" {
					copyFile(path, outFilePath)
					return nil
				}
				logrus.Infof("decrypting db %s error:%v", path, err)
			}
			return err

		}

		return nil
	})
	logrus.Debugf("filepath.Walk done")
	return err
}
func init() {
	//JPEG (jpg)，文件头：FFD8FF
	//PNG (png)，文件头：89504E47
	//GIF (gif)，文件头：47494638
	//TIFF (tif)，文件头：49492A00
	//Windows Bitmap (bmp)，文件头：424D
	const (
		Jpeg = "FFD8FF"
		Png  = "89504E47"
		Gif  = "47494638"
		Tif  = "49492A00"
		Bmp  = "424D"
	)
	JpegPrefixBytes, _ := hex.DecodeString(Jpeg)
	PngPrefixBytes, _ := hex.DecodeString(Png)
	GifPrefixBytes, _ := hex.DecodeString(Gif)
	TifPrefixBytes, _ := hex.DecodeString(Tif)
	BmpPrefixBytes, _ := hex.DecodeString(Bmp)

	imagePrefixBtsMap = map[string][]byte{
		".jpeg": JpegPrefixBytes,
		".png":  PngPrefixBytes,
		".gif":  GifPrefixBytes,
		".tif":  TifPrefixBytes,
		".bmp":  BmpPrefixBytes,
	}
}
func DecryptDat(inFile string, outFile string) error {

	sourceFile, err := os.Open(inFile)
	if err != nil {
		logrus.Println(err.Error())
		return err
	}

	var preTenBts = make([]byte, 10)
	_, _ = sourceFile.Read(preTenBts)
	decodeByte, _, er := findDecodeByte(preTenBts)
	if er != nil {
		logrus.Println(er.Error())
		return err
	}

	distFile, er := os.Create(outFile)
	if er != nil {
		logrus.Println(er.Error())
		return err
	}
	writer := bufio.NewWriter(distFile)
	_, _ = sourceFile.Seek(0, 0)
	var rBts = make([]byte, 1024)
	for {
		n, er := sourceFile.Read(rBts)
		if er != nil {
			if er == io.EOF {
				break
			}
			logrus.Println("error: ", er.Error())
			return err
		}
		for i := 0; i < n; i++ {
			_ = writer.WriteByte(rBts[i] ^ decodeByte)
		}
	}
	_ = writer.Flush()
	_ = distFile.Close()
	_ = sourceFile.Close()
	// fmt.Println("output file：", distFile.Name())

	return nil
}

var imagePrefixBtsMap = make(map[string][]byte)

func findDecodeByte(bts []byte) (byte, string, error) {
	for ext, prefixBytes := range imagePrefixBtsMap {
		deCodeByte, err := testPrefix(prefixBytes, bts)
		if err == nil {
			return deCodeByte, ext, err
		}
	}
	return 0, "", errors.New("decode fail")
}
func testPrefix(prefixBytes []byte, bts []byte) (deCodeByte byte, error error) {
	var initDecodeByte = prefixBytes[0] ^ bts[0]
	for i, prefixByte := range prefixBytes {
		if b := prefixByte ^ bts[i]; b != initDecodeByte {
			return 0, errors.New("no")
		}
	}
	return initDecodeByte, nil
}
func exportWeChatBat(a *account.Account, outDir string) error {

	datRootPath := filepath.Join(a.DataDir, "\\FileStorage\\MsgAttach")
	imageRootPath := filepath.Join(a.DataDir, "\\FileStorage\\Image")
	rootPaths := []string{datRootPath, imageRootPath}

	for i := range rootPaths {
		if !utils.Exists(rootPaths[i]) {
			continue
		}

		err := filepath.Walk(rootPaths[i], func(path string, finfo os.FileInfo, err error) error {
			if err != nil {
				logrus.Printf("filepath.Walk：%v\n", err)
				return err
			}

			if !finfo.IsDir() && strings.HasSuffix(path, ".dat") {
				relPath, err := filepath.Rel(a.DataDir, path)
				if err != nil {
					return err
				}
				outFilePath := filepath.Join(outDir, relPath)
				err = os.MkdirAll(filepath.Dir(outFilePath), 0755)
				if err != nil {
					return err
				}
				logrus.Debugf("decrypting dat %s", path)
				err = DecryptDat(path, outFilePath)
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}

	}
	return nil

}

func exportWeChatVideoAndFile(a *account.Account, outDir string) error {
	videoRootPath := filepath.Join(a.DataDir, "\\FileStorage\\Video")
	fileRootPath := filepath.Join(a.DataDir, "\\FileStorage\\File")
	cacheRootPath := filepath.Join(a.DataDir, "\\FileStorage\\Cache")
	rootPaths := []string{videoRootPath, fileRootPath, cacheRootPath}

	for i := range rootPaths {
		if !utils.Exists(rootPaths[i]) {
			continue
		}

		err := filepath.Walk(rootPaths[i], func(path string, finfo os.FileInfo, err error) error {
			if err != nil {
				logrus.Printf("filepath.Walk：%v\n", err)
				return err
			}

			if !finfo.IsDir() {
				relPath, err := filepath.Rel(a.DataDir, path)
				if err != nil {
					return err
				}
				outFilePath := filepath.Join(outDir, relPath)
				err = os.MkdirAll(filepath.Dir(outFilePath), 0755)
				if err != nil {
					return err
				}
				logrus.Debugf("copyFile file %s", path)
				_, err = copyFile(path, outFilePath)
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}

	}
	return nil

}

func copyFile(src, dst string) (int64, error) {
	sourceFile, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destFile.Close()

	bytesWritten, err := io.Copy(destFile, sourceFile)
	if err != nil {
		return bytesWritten, err
	}

	return bytesWritten, nil
}

type wechatMediaMSG struct {
	Key      string
	MsgSvrID int
	Buf      []byte
}

func exportWeChatVoice(outDir string) error {

	voiceOutPath := filepath.Join(outDir, "FileStorage", "Voice")
	if !utils.Exists(voiceOutPath) {
		if err := os.MkdirAll(voiceOutPath, 0644); err != nil {
			logrus.Infof("MkdirAll %s failed: %v", voiceOutPath, err)
			return fmt.Errorf("mkdirAll %s failed: %v", voiceOutPath, err)
		}
	}
	var wg sync.WaitGroup
	// var reportWg sync.WaitGroup
	index := -1
	MSGChan := make(chan wechatMediaMSG, 100)
	go func() {
		for {
			index += 1
			mediaMSGDB := filepath.Join(outDir, "Msg", "Multi", fmt.Sprintf("MediaMSG%d.db", index))
			if !utils.Exists(mediaMSGDB) {
				// logrus.Infof("%s不存在", mediaMSGDB)
				break
			}
			logrus.Infof("export voice from %s", mediaMSGDB)
			db, err := sql.Open("sqlite3", mediaMSGDB)
			if err != nil {
				logrus.Printf("open %s failed: %v\n", mediaMSGDB, err)
				continue
			}
			defer db.Close()

			rows, err := db.Query("select Key, Reserved0, Buf from Media;")
			if err != nil {
				logrus.Printf("Query failed: %v\n", err)
				continue
			}

			msg := wechatMediaMSG{}
			for rows.Next() {
				err := rows.Scan(&msg.Key, &msg.MsgSvrID, &msg.Buf)
				logrus.Info("Scan a voice, MsgSvrID:", msg.MsgSvrID)
				if err != nil {
					logrus.Println("Scan failed: ", err)
					break
				}

				MSGChan <- msg
			}

		}
		close(MSGChan)
	}()
	// 20个协程去解密，加快点速度
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range MSGChan {
				mp3Path := filepath.Join(voiceOutPath, fmt.Sprintf("%d.mp3", msg.MsgSvrID))
				logrus.Debugf("silkToMp3 generate %s ", mp3Path)
				if utils.Exists(mp3Path) {
					continue
				}
				// logrus.Debugf("silkToMp3 generate %s ", mp3Path)
				err := silkToMp3(msg.Buf[:], mp3Path)
				if err != nil {
					logrus.Printf("silkToMp3 %s failed: %v\n", mp3Path, err)
				}
			}
		}()
	}
	wg.Wait()
	return nil

}
func silkToMp3(amrBuf []byte, mp3Path string) error {
	amrReader := bytes.NewReader(amrBuf)

	var pcmBuffer bytes.Buffer
	sr := silk.NewWriter(&pcmBuffer)
	sr.Decoder.SetSampleRate(24000)
	amrReader.WriteTo(sr)
	sr.Close()

	if pcmBuffer.Len() == 0 {
		return errors.New("silk to mp3 failed " + mp3Path)
	}

	of, err := os.Create(mp3Path)
	if err != nil {
		return nil
	}
	defer of.Close()

	wr := lame.NewWriter(of)
	wr.Encoder.SetInSamplerate(24000)
	wr.Encoder.SetOutSamplerate(24000)
	wr.Encoder.SetNumChannels(1)
	wr.Encoder.SetQuality(5)
	// IMPORTANT!
	wr.Encoder.InitParams()

	pcmBuffer.WriteTo(wr)
	wr.Close()

	return nil
}

type wechatHeadImgMSG struct {
	userName string
	Buf      []byte
}

func exportWeChatHeadImage(outDir string) error {

	headImgOutPath := filepath.Join(outDir, "FileStorage", "HeadImage")
	if !utils.Exists(headImgOutPath) {
		if err := os.MkdirAll(headImgOutPath, 0644); err != nil {
			logrus.Printf("MkdirAll %s failed: %v\n", headImgOutPath, err)
			return fmt.Errorf("MkdirAll %s failed: %v\n", headImgOutPath, err)
		}
	}

	var wg sync.WaitGroup

	MSGChan := make(chan wechatHeadImgMSG, 100)
	go func() {
		for {
			miscDBPath := filepath.Join(outDir, "Msg", "Misc.db")
			if !utils.Exists(miscDBPath) {
				log.Println("no exist:", miscDBPath)
				break
			}

			db, err := sql.Open("sqlite3", miscDBPath)
			if err != nil {
				log.Printf("open %s failed: %v\n", miscDBPath, err)
				break
			}
			defer db.Close()
			// 读取数据库中的数据
			rows, err := db.Query("select ifnull(usrName,'') as usrName, ifnull(smallHeadBuf,'') as smallHeadBuf from ContactHeadImg1;")
			if err != nil {
				log.Printf("Query failed: %v\n", err)
				break
			}

			msg := wechatHeadImgMSG{}
			for rows.Next() {
				err := rows.Scan(&msg.userName, &msg.Buf)
				if err != nil {
					log.Println("Scan failed: ", err)
					break
				}

				MSGChan <- msg
			}
			break
		}
		close(MSGChan)
	}()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range MSGChan {
				imgPath := filepath.Join(headImgOutPath, fmt.Sprintf("%s.headimg", msg.userName))

				if len(msg.userName) != 0 && len(msg.Buf) != 0 {
					if !utils.Exists(imgPath) {
						err := os.WriteFile(imgPath, msg.Buf[:], 0666)
						if err != nil {
							log.Println("WriteFile error:", imgPath, err)
						}
					}
				}

			}
		}()
	}

	wg.Wait()
	return nil
}
