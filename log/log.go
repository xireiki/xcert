package log

import (
	"io"
	"os"
)

var std = New(os.Stderr, LevelInfo, colorSupported(os.Stderr))

func colorSupported(file *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func SetLevel(level Level) {
	std.SetLevel(level)
}

func SetWriter(writer io.Writer) {
	std.SetWriter(writer)
}

func Trace(format string, a ...any) { std.Trace(format, a...) }
func Debug(format string, a ...any) { std.Debug(format, a...) }
func Info(format string, a ...any)  { std.Info(format, a...) }
func Warn(format string, a ...any)  { std.Warn(format, a...) }
func Error(format string, a ...any) { std.Error(format, a...) }
func Fatal(format string, a ...any) { std.Fatal(format, a...) }
func Panic(format string, a ...any) { std.Panic(format, a...) }
