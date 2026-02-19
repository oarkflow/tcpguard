package tcpguard

import (
	"fmt"
	"io"
	"os"

	"github.com/oarkflow/log"
)

type SimpleLogger struct {
	logger log.Logger
}

func NewSimpleLogger() *SimpleLogger {
	return &SimpleLogger{
		logger: log.Logger{
			Writer: &log.ConsoleWriter{},
		},
	}
}

func NewFileLogger(filename string) (*SimpleLogger, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return &SimpleLogger{
		logger: log.Logger{
			Writer: &log.FileWriter{
				Filename: filename,
				FileMode: 0666,
			},
		},
	}, file.Close()
}

func (l *SimpleLogger) Close() error {
	if closer, ok := l.logger.Writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (l *SimpleLogger) Debug(msg string, fields map[string]any) {
	l.logger.Debug().Fields(fields).Msg(msg)
}

func (l *SimpleLogger) Info(msg string, fields map[string]any) {
	l.logger.Info().Fields(fields).Msg(msg)
}

func (l *SimpleLogger) Warn(msg string, fields map[string]any) {
	l.logger.Warn().Fields(fields).Msg(msg)
}

func (l *SimpleLogger) Error(msg string, fields map[string]any) {
	l.logger.Error().Fields(fields).Msg(msg)
}

func (l *SimpleLogger) log(level, msg string, fields map[string]any) {
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
	fmt.Println(logMsg)
}
