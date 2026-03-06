package logging

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"sync"
	"time"
)

// LogLevel представляет уровень важности сообщения журнала
type LogLevel string

const (
	INFO  LogLevel = "INFO"  // Информационные сообщения
	DEBUG LogLevel = "DEBUG" // Отладочные сообщения
	ERROR LogLevel = "ERROR" // Сообщения об ошибках
)

// ScanStatistics хранит метрики операций сканирования файлов
type ScanStatistics struct {
	TotalFiles    int64     // Всего обработано файлов
	TotalSize     int64     // Общий размер всех файлов
	DeletedFiles  int64     // Количество удалённых файлов
	DeletedSize   int64     // Размер удалённых файлов
	TrashedFiles  int64     // Количество перемещённых в корзину
	TrashedSize   int64     // Размер перемещённых в корзину
	IgnoredFiles  int64     // Количество проигнорированных файлов
	IgnoredSize   int64     // Размер проигнорированных файлов
	StartTime     time.Time // Время начала операции
	EndTime       time.Time // Время окончания операции
	Directory     string    // Целевая директория
	OperationType string    // Тип выполненной операции
}

// LogEntry представляет одну запись журнала с метаданными
type LogEntry struct {
	Timestamp time.Time       `json:"timestamp"`       // Время создания записи
	Level     LogLevel        `json:"level"`           // Уровень важности
	Message   string          `json:"message"`         // Текст сообщения
	Stats     *ScanStatistics `json:"stats,omitempty"` // Статистика сканирования (опционально)
}

// Logger обеспечивает запись в системный журнал (syslog) с поддержкой повторных попыток.
type Logger struct {
	mu            sync.Mutex
	debugWriter   *syslog.Writer // Writer для отладочных сообщений
	infoWriter    *syslog.Writer // Writer для информационных сообщений
	errWriter     *syslog.Writer // Writer для сообщений об ошибках
	currentScan   *ScanStatistics
	StatsCallback func(*ScanStatistics) // Колбэк при обновлении статистики
}

// NewLogger создаёт новый экземпляр Logger, подключаясь к системному журналу.
// Параметр configPath игнорируется (оставлен для обратной совместимости).
func NewLogger(configPath string, statsCallback func(*ScanStatistics)) (*Logger, error) {
	// Пытаемся создать writer для каждого уровня, чтобы сразу выявить проблемы с syslog
	debugW, err := syslog.New(syslog.LOG_DEBUG|syslog.LOG_USER, "secure_erase")
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к syslog для DEBUG: %w", err)
	}
	infoW, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "secure_erase")
	if err != nil {
		debugW.Close()
		return nil, fmt.Errorf("не удалось подключиться к syslog для INFO: %w", err)
	}
	errW, err := syslog.New(syslog.LOG_ERR|syslog.LOG_USER, "secure_erase")
	if err != nil {
		debugW.Close()
		infoW.Close()
		return nil, fmt.Errorf("не удалось подключиться к syslog для ERROR: %w", err)
	}

	return &Logger{
		debugWriter:   debugW,
		infoWriter:    infoW,
		errWriter:     errW,
		StatsCallback: statsCallback,
	}, nil
}

// Log записывает сообщение с указанным уровнем в системный журнал.
// При ошибке выполняются повторные попытки (до 3 раз) с экспоненциальной задержкой.
func (l *Logger) Log(level LogLevel, message string) error {
	// Захватываем текущую статистику для включения в запись
	l.mu.Lock()
	stats := l.currentScan
	l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Stats:     stats,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ошибка сериализации записи в JSON: %w", err)
	}

	// Выбираем соответствующий writer
	var w *syslog.Writer
	switch level {
	case DEBUG:
		w = l.debugWriter
	case INFO:
		w = l.infoWriter
	case ERROR:
		w = l.errWriter
	default:
		w = l.infoWriter // По умолчанию используем INFO
	}

	// Выполняем запись с повторными попытками
	const maxAttempts = 3
	backoff := []time.Duration{100 * time.Millisecond, 400 * time.Millisecond, 900 * time.Millisecond}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		_, err := w.Write(data)
		if err == nil {
			return nil // Успешно
		}
		lastErr = err
		if attempt < maxAttempts-1 {
			time.Sleep(backoff[attempt])
		}
	}
	return fmt.Errorf("не удалось записать в syslog после %d попыток: %w", maxAttempts, lastErr)
}

// UpdateStats обновляет текущую статистику и вызывает колбэк, если он задан.
func (l *Logger) UpdateStats(stats *ScanStatistics) {
	l.mu.Lock()
	l.currentScan = stats
	l.mu.Unlock()

	if l.StatsCallback != nil {
		l.StatsCallback(stats)
	}
}

// Close закрывает все соединения с syslog.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var lastErr error
	if l.debugWriter != nil {
		if err := l.debugWriter.Close(); err != nil {
			lastErr = err
		}
		l.debugWriter = nil
	}
	if l.infoWriter != nil {
		if err := l.infoWriter.Close(); err != nil {
			lastErr = err
		}
		l.infoWriter = nil
	}
	if l.errWriter != nil {
		if err := l.errWriter.Close(); err != nil {
			lastErr = err
		}
		l.errWriter = nil
	}
	return lastErr
}
