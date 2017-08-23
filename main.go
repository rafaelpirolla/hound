// /////////////////////////////////////////////////////////////////////////////

package main

// /////////////////////////////////////////////////////////////////////////////

import (
	"flag"
	"fmt"
	"log"
	"os"
)

// /////////////////////////////////////////////////////////////////////////////
// GLOBALS
// /////////////////////////////////////////////////////////////////////////////

var (
	configFile    string
	inputFile     string
	shouldOuput   bool
	shouldAnalyze bool
)

// /////////////////////////////////////////////////////////////////////////////
// METHODS
// /////////////////////////////////////////////////////////////////////////////

func init() {
	flag.StringVar(&configFile, "config", "", "config file path")
	flag.StringVar(&inputFile, "input", "", "read from specified pcap file")
	flag.BoolVar(&shouldOuput, "stdout", true, "show analysis result in stdout")
	flag.BoolVar(&shouldAnalyze, "analyze", false, "run analysis process")
	flag.Parse()

	if configFile == "" {
		log.Fatalln("no config files provided")
	}
}

// /////////////////////////////////////////////////////////////////////////////

func main() {
	config := NewConfig()

	err := (*config).Load(configFile)

	if err != nil {
		log.Fatalln(err.Error())
	}

	capturer, err := NewPacketCapture(config)

	if err != nil {
		log.Fatalln(err.Error())
	}

	if inputFile == "" {
		inputFile, err = capturer.StartCapture()

		if err != nil {
			log.Fatalln(err.Error())
		}

		fmt.Println("packets captured saved in file", inputFile)
	} else {
		shouldAnalyze = true
	}

	analysis, err := NewTCPAnalysis(config)

	if err != nil {
		log.Fatalln(err.Error())
	}

	if shouldAnalyze {
		connections, err := (*analysis).Run(inputFile)

		if err != nil {
			log.Fatalln(err.Error())
		}

		if shouldOuput {
			scpr := NewScreenPrinter()
			scpr.print(connections)
		}
	}

	// Start of publishing results process
	// Clean Up

	os.Exit(0)
}
