package runner

import (
	tea "github.com/charmbracelet/bubbletea"
	zone "github.com/lrstanley/bubblezone"
	"github.com/Pacmanoidum/RedDeletor/internal/filemanager"
	"github.com/Pacmanoidum/RedDeletor/internal/rules"
	"github.com/Pacmanoidum/RedDeletor/internal/tui"
	"github.com/Pacmanoidum/RedDeletor/internal/validation"
)

func RunTUI(
	filemanager filemanager.FileManager,
	rules rules.Rules, validator *validation.Validator,
) error {
	zone.NewGlobal()
	app := tui.NewApp(filemanager, rules, validator)
	p := tea.NewProgram(app, tea.WithAltScreen(), tea.WithMouseAllMotion())
	_, err := p.Run()
	return err
}
