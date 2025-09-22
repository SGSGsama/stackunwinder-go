package debug

import (
	"fmt"

	"os"
)

var IsDebug bool = false

func Debug(format string, args ...interface{}) {
	if IsDebug {
		fmt.Printf(format, args...)
	}
}
func SetDebugMode(_isDebug bool) {
	IsDebug = _isDebug
	if IsDebug {
		os.Setenv("STACKUNWINDER_DEBUG", "1") // set environment variable for Debug mode
	} else {
		os.Setenv("STACKUNWINDER_DEBUG", "0")
	}
}
