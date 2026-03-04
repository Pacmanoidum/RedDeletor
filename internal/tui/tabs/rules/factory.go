package rules

import (
	"github.com/Pacmanoidum/RedDeletor/internal/tui/interfaces"
	"github.com/Pacmanoidum/RedDeletor/internal/tui/tabs/base"
)

type RulesTabFactory struct{}

func NewRulesTabFactory() *RulesTabFactory {
	return &RulesTabFactory{}
}

func (f *RulesTabFactory) CreateTabs(model interfaces.RulesModel) []base.Tab {
	return []base.Tab{
		&MainTab{model: model},
		&FiltersTab{model: model},
		&OptionsTab{model: model},
	}
}
