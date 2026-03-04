package main

import (
	"fmt"
	"os"

	"github.com/Pacmanoidum/RedDeletor/internal/cli/config"
	"github.com/Pacmanoidum/RedDeletor/internal/filemanager"
	"github.com/Pacmanoidum/RedDeletor/internal/rules"
	"github.com/Pacmanoidum/RedDeletor/internal/runner"
	"github.com/Pacmanoidum/RedDeletor/internal/validation"
)

func main() {
	var rules = rules.NewRules()
	rules.SetupRulesConfig()
	config := config.GetFlags()
	validator := validation.NewValidator()
	fm := filemanager.NewFileManager()

	if config.IsCLIMode {
		runner.RunCLI(fm, rules, config)
	} else {
		if err := runner.RunTUI(fm, rules, validator); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}
}
