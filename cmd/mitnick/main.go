package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mitnick-security/mitnick/internal/app"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signalContext(context.Background())
	defer stop()
	if err := app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mitnick:", err)
		return app.ExitCode(err)
	}
	return 0
}
