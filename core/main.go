package main

import (
	"log"
	"os"

	"github.com/pkg/errors"

	"github.com/smartcontractkit/chainlink/core/cmd"
	"github.com/smartcontractkit/chainlink/core/config"
	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/recovery"
	"github.com/smartcontractkit/chainlink/core/sessions"
)

func main() {
	recovery.ReportPanics(func() {
		Run(NewProductionClient(), os.Args...)
	})
}

// Run runs the CLI, providing further command instructions by default.
func Run(client *cmd.Client, args ...string) {
	app := cmd.NewApp(client)
	client.Logger.ErrorIf(app.Run(args), "Error running app")
}

// NewProductionClient configures an instance of the CLI to be used
// in production.
func NewProductionClient() *cmd.Client {
	cfg, warns, err := config.NewGeneralConfig()
	if err != nil {
		log.Fatalln("Fatal configuration error:", err)
	}
	lggr := logger.NewLogger(cfg)
	for _, warn := range warns {
		lggr.Warn(warn)
	}

	prompter := cmd.NewTerminalPrompter()
	cookieAuth := cmd.NewSessionCookieAuthenticator(cfg, cmd.DiskCookieStore{Config: cfg}, lggr)
	sr := sessions.SessionRequest{}
	sessionRequestBuilder := cmd.NewFileSessionRequestBuilder(lggr)
	if credentialsFile := cfg.AdminCredentialsFile(lggr); credentialsFile != "" {
		var err error
		sr, err = sessionRequestBuilder.Build(credentialsFile)
		if err != nil && errors.Cause(err) != cmd.ErrNoCredentialFile && !os.IsNotExist(err) {
			lggr.Fatalw("Error loading API credentials", "error", err, "credentialsFile", credentialsFile)
		}
	}
	return &cmd.Client{
		Renderer:                       cmd.RendererTable{Writer: os.Stdout},
		Config:                         cfg,
		Logger:                         lggr,
		AppFactory:                     cmd.ChainlinkAppFactory{},
		KeyStoreAuthenticator:          cmd.TerminalKeyStoreAuthenticator{Prompter: prompter},
		FallbackAPIInitializer:         cmd.NewPromptingAPIInitializer(prompter),
		Runner:                         cmd.ChainlinkRunner{},
		HTTP:                           cmd.NewAuthenticatedHTTPClient(cfg, cookieAuth, sr),
		CookieAuthenticator:            cookieAuth,
		FileSessionRequestBuilder:      sessionRequestBuilder,
		PromptingSessionRequestBuilder: cmd.NewPromptingSessionRequestBuilder(prompter),
		ChangePasswordPrompter:         cmd.NewChangePasswordPrompter(),
		PasswordPrompter:               cmd.NewPasswordPrompter(),
	}
}
