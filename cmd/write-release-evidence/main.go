package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"warptweet.com/warptweet/internal/releaseevidence"
)

func main() {
	root := flag.String("root", "", "repository root (default: current directory)")
	checklistPath := flag.String("checklist", "", "checklist-v3.json path")
	inPath := flag.String("in", "", "draft evidence JSON (or - for stdin)")
	outPath := flag.String("out", "", "validated evidence output path")
	index := flag.Bool("index", false, "treat input as a v3 public index")
	flag.Parse()
	if err := run(*root, *checklistPath, *inPath, *outPath, *index); err != nil {
		fmt.Fprintf(os.Stderr, "write-release-evidence: %v\n", err)
		os.Exit(1)
	}
}

func run(root, checklistPath, inPath, outPath string, asIndex bool) error {
	if inPath == "" || outPath == "" {
		return fmt.Errorf("usage: write-release-evidence --in draft.json --out evidence.json")
	}
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		root = cwd
	}
	if checklistPath == "" {
		checklistPath = releaseevidence.DefaultChecklistV3Path(root)
	}
	checklist, err := releaseevidence.LoadChecklistV3(checklistPath)
	if err != nil {
		return fmt.Errorf("checklist: %w", err)
	}
	raw, err := readInput(inPath)
	if err != nil {
		return err
	}
	if asIndex {
		index, err := releaseevidence.DecodeIndexV3(raw)
		if err != nil {
			return fmt.Errorf("decode index: %w", err)
		}
		return releaseevidence.WriteIndexV3(outPath, checklist, index)
	}
	report, err := releaseevidence.DecodeReportV3(raw)
	if err != nil {
		return fmt.Errorf("decode report: %w", err)
	}
	if report.ContractChecklistSHA256 == "" {
		report.ContractChecklistSHA256 = checklist.FileSHA256
	}
	return releaseevidence.WriteReportV3(outPath, checklist, report)
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}
