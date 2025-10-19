package tcpguard

import (
	"fmt"
)

// SimpleLogger implements Logger with basic structured logging
type SimpleLogger struct{}

func NewSimpleLogger() *SimpleLogger {
	return &SimpleLogger{}
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
	fmt.Printf("[%s] %s", level, msg)
	if len(fields) > 0 {
		fmt.Printf(" | ")
		first := true
		for k, v := range fields {
			if !first {
				fmt.Printf(", ")
			}
			fmt.Printf("%s=%v", k, v)
			first = false
		}
	}
	fmt.Println()
}
