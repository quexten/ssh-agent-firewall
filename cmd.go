package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle  = focusedStyle
	noStyle      = lipgloss.NewStyle()
	helpStyle    = blurredStyle
)

// normalizeFingerprint ensures the SHA256 fingerprint has proper base64 padding
func normalizeFingerprint(fingerprint string) string {
	// Check if it starts with SHA256:
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		// If no prefix, assume it's just the base64 part and add the prefix
		fingerprint = "SHA256:" + fingerprint
	}

	// Extract the base64 part
	base64Part := strings.TrimPrefix(fingerprint, "SHA256:")

	// Pad the base64 to make its length a multiple of 4
	padding := (4 - len(base64Part)%4) % 4
	base64Part += strings.Repeat("=", padding)

	return "SHA256:" + base64Part
}

// addSocketModel is the bubbletea model for adding a socket
type addSocketModel struct {
	nameInput  textinput.Model
	pathInput  textinput.Model
	focusIndex int
	err        error
	done       bool
	config     *Config
	configPath string
}

func initialAddSocketModel(config *Config, configPath string) addSocketModel {
	nameInput := textinput.New()
	nameInput.Placeholder = "my-socket"
	nameInput.Focus()
	nameInput.CharLimit = 64
	nameInput.Width = 40
	nameInput.PromptStyle = focusedStyle
	nameInput.TextStyle = focusedStyle

	pathInput := textinput.New()
	pathInput.Placeholder = "/tmp/my-socket.sock"
	pathInput.CharLimit = 256
	pathInput.Width = 60
	pathInput.PromptStyle = blurredStyle
	pathInput.TextStyle = blurredStyle

	return addSocketModel{
		nameInput:  nameInput,
		pathInput:  pathInput,
		focusIndex: 0,
		config:     config,
		configPath: configPath,
	}
}

func (m addSocketModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m addSocketModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "tab", "shift+tab", "up", "down":
			s := msg.String()

			if s == "up" || s == "shift+tab" {
				m.focusIndex--
			} else {
				m.focusIndex++
			}

			if m.focusIndex > 1 {
				m.focusIndex = 0
			} else if m.focusIndex < 0 {
				m.focusIndex = 1
			}

			if m.focusIndex == 0 {
				m.nameInput.Focus()
				m.nameInput.PromptStyle = focusedStyle
				m.nameInput.TextStyle = focusedStyle
				m.pathInput.Blur()
				m.pathInput.PromptStyle = blurredStyle
				m.pathInput.TextStyle = blurredStyle
			} else {
				m.pathInput.Focus()
				m.pathInput.PromptStyle = focusedStyle
				m.pathInput.TextStyle = focusedStyle
				m.nameInput.Blur()
				m.nameInput.PromptStyle = blurredStyle
				m.nameInput.TextStyle = blurredStyle
			}

			return m, nil

		case "enter":
			name := strings.TrimSpace(m.nameInput.Value())
			path := strings.TrimSpace(m.pathInput.Value())

			if name == "" {
				m.err = fmt.Errorf("name cannot be empty")
				return m, nil
			}

			// Default path if not provided
			if path == "" {
				path = filepath.Join("/tmp", fmt.Sprintf("%s.sock", name))
			}

			// Check for duplicate names
			for _, out := range m.config.Outputs {
				if out.Name == name {
					m.err = fmt.Errorf("socket with name '%s' already exists", name)
					return m, nil
				}
			}

			// Add the new socket
			m.config.Outputs = append(m.config.Outputs, OutputConfig{
				Name: name,
				Path: path,
			})

			// Save config
			if err := SaveConfig(m.configPath, m.config); err != nil {
				m.err = err
				return m, nil
			}

			m.done = true
			return m, tea.Quit
		}
	}

	// Update the focused input
	var cmd tea.Cmd
	if m.focusIndex == 0 {
		m.nameInput, cmd = m.nameInput.Update(msg)
	} else {
		m.pathInput, cmd = m.pathInput.Update(msg)
	}

	return m, cmd
}

func (m addSocketModel) View() string {
	var b strings.Builder

	b.WriteString("Add a new socket\n\n")

	b.WriteString("Name: ")
	b.WriteString(m.nameInput.View())
	b.WriteString("\n\n")

	b.WriteString("Path: ")
	b.WriteString(m.pathInput.View())
	b.WriteString("\n\n")

	if m.err != nil {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf("Error: %v", m.err)))
		b.WriteString("\n\n")
	}

	if m.done {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("Socket added successfully!"))
		b.WriteString("\n")
	} else {
		b.WriteString(helpStyle.Render("tab/shift+tab: switch fields • enter: submit • esc: cancel"))
		b.WriteString("\n")
	}

	return b.String()
}

// removeSocketModel is the bubbletea model for removing a socket
type removeSocketModel struct {
	cursor     int
	choices    []OutputConfig
	selected   bool
	err        error
	done       bool
	config     *Config
	configPath string
}

func initialRemoveSocketModel(config *Config, configPath string) removeSocketModel {
	return removeSocketModel{
		cursor:     0,
		choices:    config.Outputs,
		config:     config,
		configPath: configPath,
	}
}

func (m removeSocketModel) Init() tea.Cmd {
	return nil
}

func (m removeSocketModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc", "q":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}

		case "enter", " ":
			if len(m.choices) == 0 {
				return m, tea.Quit
			}

			// Remove the selected socket
			selectedName := m.choices[m.cursor].Name
			newOutputs := make([]OutputConfig, 0, len(m.config.Outputs)-1)
			for _, out := range m.config.Outputs {
				if out.Name != selectedName {
					newOutputs = append(newOutputs, out)
				}
			}
			m.config.Outputs = newOutputs

			// Save config
			if err := SaveConfig(m.configPath, m.config); err != nil {
				m.err = err
				return m, nil
			}

			m.done = true
			m.selected = true
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m removeSocketModel) View() string {
	var b strings.Builder

	b.WriteString("Select a socket to remove\n\n")

	if len(m.choices) == 0 {
		b.WriteString("No sockets configured.\n")
		b.WriteString(helpStyle.Render("\nPress any key to exit."))
		return b.String()
	}

	for i, choice := range m.choices {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}

		line := fmt.Sprintf("%s %s (%s)", cursor, choice.Name, choice.Path)
		if m.cursor == i {
			b.WriteString(focusedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")

	if m.err != nil {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf("Error: %v", m.err)))
		b.WriteString("\n\n")
	}

	if m.done {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("Socket removed successfully!"))
		b.WriteString("\n")
	} else {
		b.WriteString(helpStyle.Render("j/k or ↑/↓: navigate • enter/space: select • q/esc: cancel"))
		b.WriteString("\n")
	}

	return b.String()
}

func runAddSocket() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	p := tea.NewProgram(initialAddSocketModel(config, configPath))
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	return nil
}

func runRemoveSocket() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	p := tea.NewProgram(initialRemoveSocketModel(config, configPath))
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	return nil
}

func runListSockets() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(config.Outputs) == 0 {
		fmt.Println(helpStyle.Render("No sockets configured."))
		return nil
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	nameStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	fmt.Println(titleStyle.Render("Configured sockets:"))
	fmt.Println()
	for _, out := range config.Outputs {
		fmt.Printf("  %s\n", nameStyle.Render(out.Name))
		fmt.Printf("    %s %s\n", labelStyle.Render("Path:"), valueStyle.Render(out.Path))
		if len(out.AllowedKeys) > 0 {
			fmt.Printf("    %s %s\n", labelStyle.Render("Allowed keys:"), valueStyle.Render(fmt.Sprintf("%d", len(out.AllowedKeys))))
		}
		fmt.Println()
	}

	return nil
}

// selectSocketModel is a reusable model for selecting a socket
type selectSocketModel struct {
	cursor     int
	choices    []OutputConfig
	selected   bool
	title      string
	config     *Config
	configPath string
}

func initialSelectSocketModel(config *Config, configPath, title string) selectSocketModel {
	return selectSocketModel{
		cursor:     0,
		choices:    config.Outputs,
		title:      title,
		config:     config,
		configPath: configPath,
	}
}

func (m selectSocketModel) Init() tea.Cmd {
	return nil
}

func (m selectSocketModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc", "q":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}

		case "enter", " ":
			if len(m.choices) == 0 {
				return m, tea.Quit
			}
			m.selected = true
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m selectSocketModel) View() string {
	var b strings.Builder

	b.WriteString(m.title + "\n\n")

	if len(m.choices) == 0 {
		b.WriteString("No sockets configured.\n")
		b.WriteString(helpStyle.Render("\nPress any key to exit."))
		return b.String()
	}

	for i, choice := range m.choices {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}

		line := fmt.Sprintf("%s %s (%s)", cursor, choice.Name, choice.Path)
		if m.cursor == i {
			b.WriteString(focusedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("j/k or ↑/↓: navigate • enter/space: select • q/esc: cancel"))
	b.WriteString("\n")

	return b.String()
}

// addKeyModel is the bubbletea model for adding a key to a socket
type addKeyModel struct {
	keyInput    textinput.Model
	socketIndex int
	err         error
	done        bool
	config      *Config
	configPath  string
}

func initialAddKeyModel(config *Config, configPath string, socketIndex int) addKeyModel {
	keyInput := textinput.New()
	keyInput.Placeholder = "SHA256:..."
	keyInput.Focus()
	keyInput.CharLimit = 256
	keyInput.Width = 60
	keyInput.PromptStyle = focusedStyle
	keyInput.TextStyle = focusedStyle

	return addKeyModel{
		keyInput:    keyInput,
		socketIndex: socketIndex,
		config:      config,
		configPath:  configPath,
	}
}

func (m addKeyModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m addKeyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "enter":
			key := strings.TrimSpace(m.keyInput.Value())

			if key == "" {
				m.err = fmt.Errorf("key fingerprint cannot be empty")
				return m, nil
			}

			// Normalize the key fingerprint
			key = normalizeFingerprint(key)

			// Check for duplicate keys
			for _, existingKey := range m.config.Outputs[m.socketIndex].AllowedKeys {
				if existingKey == key {
					m.err = fmt.Errorf("key already exists for this socket")
					return m, nil
				}
			}

			// Add the key
			m.config.Outputs[m.socketIndex].AllowedKeys = append(
				m.config.Outputs[m.socketIndex].AllowedKeys,
				key,
			)

			// Save config
			if err := SaveConfig(m.configPath, m.config); err != nil {
				m.err = err
				return m, nil
			}

			m.done = true
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.keyInput, cmd = m.keyInput.Update(msg)
	return m, cmd
}

func (m addKeyModel) View() string {
	var b strings.Builder

	socketName := m.config.Outputs[m.socketIndex].Name
	b.WriteString(fmt.Sprintf("Add a key to socket '%s'\n\n", socketName))

	b.WriteString("Key fingerprint: ")
	b.WriteString(m.keyInput.View())
	b.WriteString("\n\n")

	if m.err != nil {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf("Error: %v", m.err)))
		b.WriteString("\n\n")
	}

	if m.done {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("Key added successfully!"))
		b.WriteString("\n")
	} else {
		b.WriteString(helpStyle.Render("enter: submit • esc: cancel"))
		b.WriteString("\n")
	}

	return b.String()
}

// removeKeyModel is the bubbletea model for removing a key from a socket
type removeKeyModel struct {
	cursor      int
	keys        []string
	socketIndex int
	err         error
	done        bool
	config      *Config
	configPath  string
}

func initialRemoveKeyModel(config *Config, configPath string, socketIndex int) removeKeyModel {
	return removeKeyModel{
		cursor:      0,
		keys:        config.Outputs[socketIndex].AllowedKeys,
		socketIndex: socketIndex,
		config:      config,
		configPath:  configPath,
	}
}

func (m removeKeyModel) Init() tea.Cmd {
	return nil
}

func (m removeKeyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc", "q":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.keys)-1 {
				m.cursor++
			}

		case "enter", " ":
			if len(m.keys) == 0 {
				return m, tea.Quit
			}

			// Remove the selected key
			selectedKey := m.keys[m.cursor]
			newKeys := make([]string, 0, len(m.keys)-1)
			for _, key := range m.config.Outputs[m.socketIndex].AllowedKeys {
				if key != selectedKey {
					newKeys = append(newKeys, key)
				}
			}
			m.config.Outputs[m.socketIndex].AllowedKeys = newKeys

			// Save config
			if err := SaveConfig(m.configPath, m.config); err != nil {
				m.err = err
				return m, nil
			}

			m.done = true
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m removeKeyModel) View() string {
	var b strings.Builder

	socketName := m.config.Outputs[m.socketIndex].Name
	b.WriteString(fmt.Sprintf("Remove a key from socket '%s'\n\n", socketName))

	if len(m.keys) == 0 {
		b.WriteString("No keys configured for this socket.\n")
		b.WriteString(helpStyle.Render("\nPress any key to exit."))
		return b.String()
	}

	for i, key := range m.keys {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}

		line := fmt.Sprintf("%s %s", cursor, key)
		if m.cursor == i {
			b.WriteString(focusedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")

	if m.err != nil {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf("Error: %v", m.err)))
		b.WriteString("\n\n")
	}

	if m.done {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("Key removed successfully!"))
		b.WriteString("\n")
	} else {
		b.WriteString(helpStyle.Render("j/k or ↑/↓: navigate • enter/space: select • q/esc: cancel"))
		b.WriteString("\n")
	}

	return b.String()
}

func runAddKey() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(config.Outputs) == 0 {
		fmt.Println("No sockets configured. Add a socket first.")
		return nil
	}

	// First, select a socket
	selectModel := initialSelectSocketModel(config, configPath, "Select a socket to add a key to")
	p := tea.NewProgram(selectModel)
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	sm := finalModel.(selectSocketModel)
	if !sm.selected {
		return nil
	}

	// Now add the key
	p = tea.NewProgram(initialAddKeyModel(config, configPath, sm.cursor))
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	return nil
}

func runRemoveKey() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(config.Outputs) == 0 {
		fmt.Println("No sockets configured.")
		return nil
	}

	// First, select a socket
	selectModel := initialSelectSocketModel(config, configPath, "Select a socket to remove a key from")
	p := tea.NewProgram(selectModel)
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	sm := finalModel.(selectSocketModel)
	if !sm.selected {
		return nil
	}

	if len(config.Outputs[sm.cursor].AllowedKeys) == 0 {
		fmt.Printf("No keys configured for socket '%s'.\n", config.Outputs[sm.cursor].Name)
		return nil
	}

	// Now remove the key
	p = tea.NewProgram(initialRemoveKeyModel(config, configPath, sm.cursor))
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	return nil
}

func runListKeys() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(config.Outputs) == 0 {
		fmt.Println(helpStyle.Render("No sockets configured."))
		return nil
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	nameStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true)

	fmt.Println(titleStyle.Render("Configured keys by socket:"))
	fmt.Println()
	for _, out := range config.Outputs {
		fmt.Printf("  %s\n", nameStyle.Render(out.Name+":"))
		if len(out.AllowedKeys) == 0 {
			fmt.Printf("    %s\n", dimStyle.Render("(all keys allowed)"))
		} else {
			for _, key := range out.AllowedKeys {
				fmt.Printf("    %s %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("-"), keyStyle.Render(key))
			}
		}
		fmt.Println()
	}

	return nil
}

func printUsage() {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	cmdStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	descStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	exampleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))

	fmt.Printf("%s ssh-proxy <command>\n", titleStyle.Render("Usage:"))
	fmt.Println()
	fmt.Println(titleStyle.Render("Commands:"))
	fmt.Printf("  %s  %s\n", cmdStyle.Render("serve        "), descStyle.Render("Start the SSH agent proxy"))
	fmt.Printf("  %s  %s\n", cmdStyle.Render("socket add   "), descStyle.Render("Add a new socket configuration"))
	fmt.Printf("  %s  %s\n", cmdStyle.Render("socket remove"), descStyle.Render("Remove a socket configuration"))
	fmt.Printf("  %s  %s\n", cmdStyle.Render("socket list  "), descStyle.Render("List all socket configurations"))
	fmt.Printf("  %s  %s\n", cmdStyle.Render("key add      "), descStyle.Render("Add a key to a socket"))
	fmt.Printf("  %s  %s\n", cmdStyle.Render("key remove   "), descStyle.Render("Remove a key from a socket"))
	fmt.Printf("  %s  %s\n", cmdStyle.Render("key list     "), descStyle.Render("List all keys by socket"))
	fmt.Println()
	fmt.Println(titleStyle.Render("Examples:"))
	fmt.Printf("  %s\n", exampleStyle.Render("ssh-proxy serve"))
	fmt.Printf("  %s\n", exampleStyle.Render("ssh-proxy socket add"))
	fmt.Printf("  %s\n", exampleStyle.Render("ssh-proxy socket remove"))
	fmt.Printf("  %s\n", exampleStyle.Render("ssh-proxy socket list"))
	fmt.Printf("  %s\n", exampleStyle.Render("ssh-proxy key add"))
	fmt.Printf("  %s\n", exampleStyle.Render("ssh-proxy key remove"))
	fmt.Printf("  %s\n", exampleStyle.Render("ssh-proxy key list"))
}

func runCommand() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	switch os.Args[1] {
	case "serve":
		return runServe()
	case "socket":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ssh-proxy socket <add|remove|list>")
			return nil
		}
		switch os.Args[2] {
		case "add":
			return runAddSocket()
		case "remove":
			return runRemoveSocket()
		case "list":
			return runListSockets()
		default:
			fmt.Printf("Unknown socket command: %s\n", os.Args[2])
			printUsage()
			return nil
		}
	case "key":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ssh-proxy key <add|remove|list>")
			return nil
		}
		switch os.Args[2] {
		case "add":
			return runAddKey()
		case "remove":
			return runRemoveKey()
		case "list":
			return runListKeys()
		default:
			fmt.Printf("Unknown key command: %s\n", os.Args[2])
			printUsage()
			return nil
		}
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		return nil
	}
}
