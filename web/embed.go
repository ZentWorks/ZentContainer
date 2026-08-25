package web

import (
	"embed"
	"fmt"
)

//go:embed dist/*
var assets embed.FS

//go:embed openapi.yaml
var apiSpec []byte

func Read(name string) ([]byte, error) { return assets.ReadFile("dist/" + name) }
func OpenAPI() ([]byte, error) {
	if len(apiSpec) == 0 {
		return nil, fmt.Errorf("OpenAPI spec unavailable")
	}
	return apiSpec, nil
}
