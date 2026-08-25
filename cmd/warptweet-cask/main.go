package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"warptweet.com/warptweet/internal/releasemetadata"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("warptweet-cask", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.String("version", "", "exact release version")
	arm64 := flags.String("sha256-arm64", "", "darwin-arm64 package SHA-256")
	ownerRepo := flags.String("github", "warptweet/warptweet", "GitHub owner/repo for release assets")
	template := flags.String("template", "", "absolute cask template path")
	output := flags.String("output", "", "optional output path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	templatePath := *template
	if templatePath == "" {
		root, err := os.Getwd()
		if err != nil {
			return err
		}
		templatePath = filepath.Join(root, "homebrew", "Casks", "warptweet.rb.tmpl")
	}
	if !filepath.IsAbs(templatePath) {
		abs, err := filepath.Abs(templatePath)
		if err != nil {
			return err
		}
		templatePath = abs
	}
	rendered, err := releasemetadata.RenderCask(releasemetadata.CaskInput{
		Version:         *version,
		SHA256ARM64:     *arm64,
		GitHubOwnerRepo: *ownerRepo,
		TemplatePath:    templatePath,
	})
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = io.WriteString(stdout, rendered)
		return err
	}
	return os.WriteFile(*output, []byte(rendered), 0o644)
}
