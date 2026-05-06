package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samaasi/go-waf/internal/compiler"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/platform/logger"
)

func main() {
	inputDir := flag.String("input", "", "Directory containing ModSecurity .conf files")
	outputDir := flag.String("output", "", "Directory to output translated YAML rules")
	flag.Parse()

	if *inputDir == "" || *outputDir == "" {
		fmt.Println("Usage: seclang-compiler --input <path> --output <path>")
		os.Exit(1)
	}

	zapLogger := logger.Init("info")
	log := logger.NewZapAdapter(zapLogger)

	log.Info("Starting SecLang Compiler", domain.String("input", *inputDir), domain.String("output", *outputDir))

	comp := compiler.NewCompiler(log)

	files, err := filepath.Glob(filepath.Join(*inputDir, "*.conf"))
	if err != nil {
		log.Error("Failed to list input directory", domain.Any("error", err))
		os.Exit(1)
	}

	if len(files) == 0 {
		log.Warn("No .conf files found in input directory")
		os.Exit(0)
	}

	var allRules []compiler.ParsedRule

	for _, file := range files {
		log.Info("Parsing file", domain.String("file", file))
		rules, err := comp.ParseFile(file)
		if err != nil {
			log.Error("Failed to parse file", domain.String("file", file), domain.Any("error", err))
			continue
		}
		allRules = append(allRules, rules...)
	}

	log.Info("Parsing complete", domain.Int("total_rules", len(allRules)))

	if err := compiler.GenerateYAML(allRules, *outputDir); err != nil {
		log.Error("Failed to generate YAML", domain.Any("error", err))
		os.Exit(1)
	}

	log.Info("Successfully compiled SecLang rules to YAML")
}
