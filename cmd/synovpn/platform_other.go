//go:build !linux

package main

import (
	"context"
	"errors"
	"synovpn/internal/config"
)

func supervise(context.Context, config.Config, string) error {
	return errors.New("the production supervisor runs only on Synology DSM Linux")
}
func webSocketPermission(string) error {
	return errors.New("production Unix sockets require DSM Linux")
}

func runContainerEngine(context.Context, []string) error {
	return errors.New("container engine requires Linux")
}
