package tcpguard

import (
	"fmt"
	"os"
	"sync"
)

// SimpleLogger implements Logger with basic structured logging
type SimpleLogger struct {
	file *os.File
	mu   sync.Mutex
}

func NewSimpleLogger() *SimpleLogger {
	return &SimpleLogger{}
}

func NewFileLogger(filename string) (*SimpleLogger, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return &SimpleLogger{file: file}, nil
}

func (l *SimpleLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *SimpleLogger) Debug(msg string, fields map[string]any) {
	l.log("DEBUG", msg, fields)
}

func (l *SimpleLogger) Info(msg string, fields map[string]any) {
	l.log("INFO", msg, fields)
}

func (l *SimpleLogger) Warn(msg string, fields map[string]any) {
	l.log("WARN", msg, fields)
}

func (l *SimpleLogger) Error(msg string, fields map[string]any) {
	l.log("ERROR", msg, fields)
}

func (l *SimpleLogger) log(level, msg string, fields map[string]any) {
	// Simple implementation - in production, use a proper structured logger
	logMsg := fmt.Sprintf("[%s] %s", level, msg)
	if len(fields) > 0 {
		logMsg += " | "
		first := true
		for k, v := range fields {
			if !first {
				logMsg += ", "
			}
			logMsg += fmt.Sprintf("%s=%v", k, v)
			first = false
		}
	}
	logMsg += "\n"

	// Log to console
	fmt.Print(logMsg)

	// Log to file if available
	if l.file != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.file.WriteString(logMsg)
	}
}
