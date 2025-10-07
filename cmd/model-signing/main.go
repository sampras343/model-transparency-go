//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sigstore/model-signing/cmd/model-signing/cli"
)

type ExitCoder interface {
	error
	ExitCode() int
}

func main() {
	log.SetFlags(0)

	for i, arg := range os.Args {

		if (strings.HasPrefix(arg, "-") && len(arg) == 2) ||
			(strings.HasPrefix(arg, "--") && len(arg) >= 4) {
			continue
		}

		if strings.HasPrefix(arg, "--") && len(arg) == 3 {
			newArg := fmt.Sprintf("-%c", arg[2])
			log.Printf("warning: the flag %s is deprecated and will be removed in a future release. Please use %s.", arg, newArg)
			os.Args[i] = newArg
			continue
		}

		if strings.HasPrefix(arg, "-") && len(arg) > 1 && !strings.HasPrefix(arg, "--") {
			newArg := fmt.Sprintf("-%s", arg)
			argType := "flag"

			if newArg == "--version" {
				newArg = "version"
				argType = "subcommand"
			}
			log.Printf("warning: the %s flag is deprecated and will be removed in a future release. Please use the %s %s instead.",
				arg, newArg, argType)

			os.Args[i] = newArg
		}
	}

	if err := cli.New().Execute(); err != nil {
		var ec ExitCoder
		if errors.As(err, &ec) {
			log.Printf("error during command execution: %v", err)
			os.Exit(ec.ExitCode())
		}

		log.Fatalf("error during command execution: %v", err)
	}
}
