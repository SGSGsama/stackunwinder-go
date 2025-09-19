package debug

import (
	"log"
	"os"
)

var IsDebug bool = false

func Debug(format string, args ...interface{}) {
	if IsDebug {
		log.Printf(format, args...)
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
