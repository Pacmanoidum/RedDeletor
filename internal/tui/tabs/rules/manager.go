package rules

import (
	"github.com/Pacmanoidum/RedDeletor/internal/tui/interfaces"
	"github.com/Pacmanoidum/RedDeletor/internal/tui/tabs/base"
)

type RulesTabManager struct {
	model     interfaces.RulesModel
	tabs      []base.Tab
	activeTab int
}

func NewRulesTabManager(model interfaces.RulesModel, factory *RulesTabFactory) *RulesTabManager {
	tabs := factory.CreateTabs(model)
	return &RulesTabManager{
		model:     model,
		tabs:      tabs,
		activeTab: 0,
	}
}

func (m *RulesTabManager) GetActiveTab() base.Tab {
	return m.tabs[m.activeTab]
}

func (m *RulesTabManager) GetActiveTabIndex() int {
	return m.activeTab
}

func (m *RulesTabManager) SetActiveTabIndex(index int) {
	if index >= 0 && index < len(m.tabs) {
		m.activeTab = index
	}
}

func (m *RulesTabManager) GetAllTabs() []base.Tab {
	return m.tabs
}
