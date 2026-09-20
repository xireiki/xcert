package log

import (
	"io"
	"os"
)

var std = New(os.Stderr, LevelInfo, os.Getenv("TERM") == "xterm-256color")

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
