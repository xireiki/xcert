package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Logger struct {
	mu     sync.Mutex
	writer io.Writer
	level  Level
	colors bool
}

func New(writer io.Writer, level Level, colors bool) *Logger {
	if writer == nil {
		writer = os.Stderr
	}
	return &Logger{writer: writer, level: level, colors: colors}
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

func (l *Logger) SetWriter(writer io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer = writer
}

func (l *Logger) log(level Level, format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level > l.level {
		return
	}
	label := strings.ToUpper(FormatLevel(level))
	if l.colors {
		label = colorize(level, label)
	}
	message := strings.TrimSuffix(fmt.Sprintf(format, a...), "\n")
	fmt.Fprintf(l.writer, "%s %s\n", label, message)
}

func (l *Logger) Trace(format string, a ...any) { l.log(LevelTrace, format, a...) }
func (l *Logger) Debug(format string, a ...any) { l.log(LevelDebug, format, a...) }
func (l *Logger) Info(format string, a ...any)  { l.log(LevelInfo, format, a...) }
func (l *Logger) Warn(format string, a ...any)  { l.log(LevelWarn, format, a...) }
func (l *Logger) Error(format string, a ...any) { l.log(LevelError, format, a...) }

func (l *Logger) Fatal(format string, a ...any) {
	l.log(LevelFatal, format, a...)
	os.Exit(1)
}

func (l *Logger) Panic(format string, a ...any) {
	l.log(LevelPanic, format, a...)
	panic(fmt.Sprintf(format, a...))
}

func colorize(level Level, label string) string {
	switch level {
	case LevelDebug, LevelTrace:
		return "\033[37m" + label + "\033[0m"
	case LevelInfo:
		return "\033[36m" + label + "\033[0m"
	case LevelWarn:
		return "\033[33m" + label + "\033[0m"
	default:
		return "\033[31m" + label + "\033[0m"
	}
}
