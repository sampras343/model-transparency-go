// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package options

import (
	"github.com/sigstore/model-signing/pkg/logging"
)

// Observability holds the shared observability configuration for the CLI.
// Logger is configured from root flags (level, format); tracing is handled
// globally via pkg/tracing (initialized in main, used via tracing.Run).
type Observability struct {
	Logger logging.Logger
}

// NewObservability returns an Observability with a logger built from root
// options. Tracing is configured globally at startup (see tracing.InitFromEnv)
// and accessed via tracing.Run / tracing.Start, so it does not need to be
// stored here.
func (o *RootOptions) NewObservability() Observability {
	return Observability{
		Logger: o.NewLogger(),
	}
}
