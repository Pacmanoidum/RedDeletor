package filemanager

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bios-Marcel/wastebasket/v2"
	"github.com/Pacmanoidum/RedDeletor/internal/utils"
)

// isSSD определяет, является ли устройство, на котором расположен файл, твердотельным накопителем.
func isSSD(path string) bool {
	device, err := getDeviceFromPath(path)
	if err != nil {
		return false
	}
	base := getBaseDeviceName(device)
	rotationalPath := filepath.Join("/sys/block", base, "queue/rotational")
	data, err := os.ReadFile(rotationalPath)
	if err != nil {
		return false
	}
	// rotational = 0 означает SSD
	return strings.TrimSpace(string(data)) == "0"
}

// getDeviceFromPath возвращает путь к блочному устройству (например, /dev/sda),
// на котором находится файл path, используя команду df.
func getDeviceFromPath(path string) (string, error) {
	cmd := exec.Command("df", "-P", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("df failed: %w, output: %s", err, out)
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	// Пропускаем заголовок
	if !scanner.Scan() {
		return "", errors.New("unexpected empty output from df")
	}
	if !scanner.Scan() {
		return "", errors.New("no data line in df output")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) == 0 {
		return "", errors.New("cannot parse df output")
	}
	// Первое поле – устройство
	return fields[0], nil
}

// getBaseDeviceName возвращает имя базового блочного устройства (например, sda из /dev/sda1)
func getBaseDeviceName(device string) string {
	// Убираем префикс /dev/
	base := strings.TrimPrefix(device, "/dev/")
	// Удаляем номера разделов (цифры в конце)
	base = strings.TrimRightFunc(base, func(r rune) bool {
		return r >= '0' && r <= '9'
	})
	// Если остался символ 'p' (для NVMe разделов), удаляем его
	if strings.HasSuffix(base, "p") {
		base = strings.TrimSuffix(base, "p")
	}
	return base
}

// Реализация методов удаления
// Криптографическое стирание, удаляет все данные, удаляя ключ шифрования.
func cryptoScrambleDelete(path string) error {
	device, err := getDeviceFromPath(path)
	if err != nil {
		return fmt.Errorf("failed to determine device for path %s: %w", path, err)
	}

	// Проверяем, является ли устройство NVMe (по наличию "nvme" в имени)
	if strings.Contains(device, "nvme") {
		// Для NVMe используем команду: nvme sanitize -a 5 <device>
		// -a 5 означает action 5 (crypto scramble)
		cmd := exec.Command("nvme", "sanitize", "-a", "5", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nvme sanitize crypto scramble failed: %w, output: %s", err, output)
		}
	} else {
		// Для SATA используем hdparm с опцией --sanitize-crypto-scramble
		cmd := exec.Command("hdparm", "--sanitize-crypto-scramble", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("hdparm sanitize crypto scramble failed: %w, output: %s", err, output)
		}
	}
	return nil
}

// blockEraseDelete выполняет санитарное стирание методом Block Erase для всего накопителя,
// на котором расположен файл path. Для SATA используется hdparm, для NVMe – nvme-cli.
// Возвращает ошибку, если устройство не поддерживает команду или выполнение не удалось.
func blockEraseDelete(path string) error {
	device, err := getDeviceFromPath(path)
	if err != nil {
		return fmt.Errorf("failed to determine device for path %s: %w", path, err)
	}

	// Проверяем, является ли устройство NVMe (по наличию "nvme" в имени)
	if strings.Contains(device, "nvme") {
		// Для NVMe используем команду: nvme sanitize -a 2 <device>
		// -a 2 означает action 2 (block erase)
		cmd := exec.Command("nvme", "sanitize", "-a", "2", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nvme sanitize block erase failed: %w, output: %s", err, output)
		}
	} else {
		// Для SATA используем hdparm с опцией --sanitize-block-erase
		cmd := exec.Command("hdparm", "--sanitize-block-erase", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("hdparm sanitize block erase failed: %w, output: %s", err, output)
		}
	}
	return nil
}

// combinedDelete выполняет комбинированный метод безопасного удаления для всего накопителя,
// на котором расположен файл path. Метод применяется, когда аппаратные команды недоступны.
// Алгоритм включает полное заполнение устройства случайными данными, принудительный TRIM,
// сброс кешей и повторное заполнение.
func combinedDelete(path string) error {
	device, err := getDeviceFromPath(path)
	if err != nil {
		return fmt.Errorf("failed to determine device for path %s: %w", path, err)
	}

	// Этап 1: Полное заполнение накопителя случайными данными
	if err := fillDeviceWithRandom(device); err != nil {
		return fmt.Errorf("stage 1 (initial fill) failed: %w", err)
	}

	// Этап 2: Принудительный TRIM всего устройства
	if err := discardDevice(device); err != nil {
		return fmt.Errorf("stage 2 (TRIM) failed: %w", err)
	}

	// Этап 3: Сброс кешей
	if err := flushCaches(device); err != nil {
		return fmt.Errorf("stage 3 (cache flush) failed: %w", err)
	}

	// Этап 4: Повторное заполнение случайными данными
	if err := fillDeviceWithRandom(device); err != nil {
		return fmt.Errorf("stage 4 (secondary fill) failed: %w", err)
	}

	// Этап 5: Верификация будет выполнена отдельным блоком (в другом месте)
	return nil
}

// fillDeviceWithRandom заполняет всё устройство случайными данными из /dev/urandom.
// Используется dd с блоком 1 МБ и принудительной синхронизацией.
func fillDeviceWithRandom(device string) error {
	cmd := exec.Command("dd", "if=/dev/urandom", "of="+device, "bs=1M", "conv=fsync", "status=progress")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dd failed: %w, output: %s", err, output)
	}
	return nil
}

// discardDevice отправляет команду TRIM на всё устройство с помощью blkdiscard.
func discardDevice(device string) error {
	cmd := exec.Command("blkdiscard", device)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("blkdiscard failed: %w, output: %s", err, output)
	}
	return nil
}

// flushCaches сбрасывает кеши операционной системы и кеши самого устройства.
// Выполняет sync, а затем для SATA-устройств вызывает hdparm -f (ошибка игнорируется,
// так как некоторые устройства могут не поддерживать эту команду).
func flushCaches(device string) error {
	// Глобальная синхронизация
	if err := exec.Command("sync").Run(); err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}
	// Для дисков, поддерживающих кеши, сбрасываем их через hdparm
	cmd := exec.Command("hdparm", "-f", device)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Не все устройства поддерживают hdparm, поэтому просто логируем, но не прерываем операцию
		// В реальном проекте можно записать предупреждение в лог, но здесь возвращаем ошибку,
		// чтобы не скрывать проблемы. Можно сделать опциональным.
		return fmt.Errorf("hdparm -f failed (optional): %w, output: %s", err, output)
	}
	return nil
}

// TODO: Разобраться с этой переменной
// Зачем  это нужно?
var ErrBlockEraseNotSupported = errors.New("block erase not supported on this device")

// combinedFileDelete выполняет комбинированное безопасное удаление одного файла.
// Алгоритм:
// 1. Многопроходная перезапись файла случайными данными (3 прохода).
// 2. Сброс кешей файла и системный sync.
// 3. Попытка принудительного TRIM на диапазон файла (через fallocate).
// 4. Удаление файла.
// Верификация и протоколирование выполняются в вызывающем коде.
func combinedFileDelete(path string) error {
	// Открываем файл для записи
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open file for overwrite: %w", err)
	}
	defer f.Close()

	// Получаем размер файла
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat file: %w", err)
	}
	size := info.Size()
	if size == 0 {
		// Пустой файл – просто удаляем
		f.Close()
		return os.Remove(path)
	}

	// Количество проходов (можно вынести в конфигурацию)
	const passes = 3

	// Буфер для случайных данных (1 МБ для эффективности)
	bufSize := 1024 * 1024
	buf := make([]byte, bufSize)

	for pass := 0; pass < passes; pass++ {
		if err := overwriteFileWithRandom(f, size, buf); err != nil {
			return fmt.Errorf("pass %d failed: %w", pass+1, err)
		}
		// Принудительный сброс на диск после каждого прохода
		if err := f.Sync(); err != nil {
			return fmt.Errorf("sync after pass %d failed: %w", pass+1, err)
		}
		// Перематываем в начало для следующего прохода
		if _, err := f.Seek(0, 0); err != nil {
			return fmt.Errorf("seek failed after pass %d: %w", pass+1, err)
		}
	}

	// Закрываем файл перед дальнейшими действиями
	f.Close()

	// Глобальная синхронизация
	if err := exec.Command("sync").Run(); err != nil {
		return fmt.Errorf("system sync failed: %w", err)
	}

	// // Попытка TRIM области файла (если файловая система поддерживает)
	// if err := discardFileRange(path, size); err != nil {
	// 	// Не фатально, только логируем (можно передать ошибку выше, но не прерываем удаление)
	// 	_ = err // в реальном коде здесь должно быть логирование
	// }

	// Финальное удаление файла
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("final remove failed: %w", err)
	}

	return nil
}

// overwriteFileWithRandom заполняет файл случайными данными, используя переданный буфер.
// Предполагается, что файл открыт на запись и позиция находится в нужном месте.
func overwriteFileWithRandom(f *os.File, size int64, buf []byte) error {
	var written int64
	for written < size {
		// Читаем случайные данные в буфер
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("rand.Read failed: %w", err)
		}
		// Определяем, сколько записать (не более размера файла)
		toWrite := int64(len(buf))
		if remaining := size - written; remaining < toWrite {
			toWrite = remaining
		}
		n, err := f.Write(buf[:toWrite])
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		written += int64(n)
	}
	return nil
}

// WalkFilesWithFilter traverses files in a directory with concurrent processing
// and applies the given filter to each file
func (f *defaultFileManager) WalkFilesWithFilter(callback func(fi os.FileInfo, path string), dir string, filter *FileFilter) {
	taskCh := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info == nil {
			return nil
		}

		if err != nil {
			return nil
		}

		wg.Add(1)
		go func(path string, info os.FileInfo) {
			defer wg.Done()
			// Acquire token from channel first
			taskCh <- struct{}{}
			defer func() { <-taskCh }() // Release token when done
			if filter.MatchesFilters(info, path) {
				callback(info, path)
			}
		}(path, info)
		return nil
	})

	wg.Wait()
}

// DeleteFiles removes files matching the specified criteria from the given directory
func (f *defaultFileManager) DeleteFiles(dir string, extensions []string, exclude []string, minSize, maxSize int64, olderThan, newerThan time.Time) {
	callback := func(fi os.FileInfo, path string) {
		os.Remove(path)
	}
	fileFilter := f.NewFileFilter(minSize, maxSize, utils.ParseExtToMap(extensions), exclude, olderThan, newerThan)
	f.WalkFilesWithFilter(callback, dir, fileFilter)
}

// DeleteEmptySubfolders removes all empty directories in the given path
func (f *defaultFileManager) DeleteEmptySubfolders(dir string) {
	emptyDirs := make([]string, 0)

	filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if info == nil || !info.IsDir() {
			return nil
		}

		if f.IsEmptyDir(path) {
			emptyDirs = append(emptyDirs, path)
		}

		return nil
	})

	for i := len(emptyDirs) - 1; i >= 0; i-- {
		os.Remove(emptyDirs[i])
	}
}

// CalculateDirSize computes the total size of all files in a directory
// Uses concurrent processing with limits to handle large directories efficiently
func (f *defaultFileManager) CalculateDirSize(path string) int64 {
	// For very large directories, return a placeholder value immediately
	// to avoid blocking the UI
	_, err := os.Stat(path)
	if err != nil {
		return 0
	}

	// If it's a very large directory (like C: or Program Files)
	// just return 0 immediately to prevent lag
	if strings.HasSuffix(path, ":\\") || strings.Contains(path, "Program Files") {
		return 0
	}

	var totalSize int64 = 0

	// Use a channel to limit concurrency
	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	// Create a function to process a directory
	var processDir func(string) int64
	processDir = func(dirPath string) int64 {
		var size int64 = 0
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			return 0
		}

		for _, entry := range entries {
			// Skip hidden files and directories unless enabled
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			fullPath := filepath.Join(dirPath, entry.Name())
			if entry.IsDir() {
				// Process directories with concurrency limits
				wg.Add(1)
				go func(p string) {
					semaphore <- struct{}{}
					defer func() {
						<-semaphore
						wg.Done()
					}()
					dirSize := processDir(p)
					atomic.AddInt64(&totalSize, dirSize)
				}(fullPath)
			} else {
				// Process files directly
				info, err := entry.Info()
				if err == nil {
					fileSize := info.Size()
					atomic.AddInt64(&totalSize, fileSize)
					size += fileSize
				}
			}
		}
		return size
	}

	// Start processing
	processDir(path)

	wg.Wait()

	return totalSize
}

// MoveFilesToTrash moves files matching the criteria to the system's recycle bin
func (f *defaultFileManager) MoveFilesToTrash(dir string, extensions []string, exclude []string, minSize, maxSize int64, olderThan, newerThan time.Time) {
	callback := func(fi os.FileInfo, path string) {
		f.MoveFileToTrash(path)
	}

	fileFilter := f.NewFileFilter(minSize, maxSize, utils.ParseExtToMap(extensions), exclude, olderThan, newerThan)
	f.WalkFilesWithFilter(callback, dir, fileFilter)
}

// MoveFileToTrash moves a single file to the system's recycle bin
func (f *defaultFileManager) MoveFileToTrash(filePath string) {
	wastebasket.Trash(filePath)
}

// DeleteFile deletes a single file
func (f *defaultFileManager) DeleteFile(filePath string) {
	os.Remove(filePath)
}
