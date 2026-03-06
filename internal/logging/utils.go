package logging

import (
	"os"
	"path/filepath"

	"github.com/Pacmanoidum/RedDeletor/internal/path"
)

// GetLogFilePath returns the path to the application's log file
// The log file is stored in the user's config directory under the app's directory
func GetLogFilePath() string {
	userConfigDir, _ := os.UserConfigDir()
	fileLogPath := filepath.Join(userConfigDir, path.AppDirName, path.LogFileName)

	return fileLogPath
}
