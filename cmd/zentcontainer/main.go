package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ZentWorks/ZentContainer/internal/app"
	"github.com/ZentWorks/ZentContainer/internal/config"
	"github.com/ZentWorks/ZentContainer/internal/version"
	"github.com/ZentWorks/ZentContainer/internal/volumehelper"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version.Version)
			return
		case "helper":
			if err := volumehelper.Run(os.Args[2:]); err != nil {
				log.Fatal(err)
			}
			return
		case "doctor":
			if err := app.Doctor(config.Load()); err != nil {
				log.Fatal(err)
			}
			return
		}
	}
	if err := app.Run(config.Load()); err != nil {
		log.Fatal(err)
	}
}
