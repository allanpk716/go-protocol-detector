package pkg

/*
SDK dependency placeholder.
This blank import ensures the SDK dependency (github.com/allanpk716/ai-agent-cli-rules/sdks/go)
is retained in go.mod via `go mod tidy`. The import runs only the SDK package's init functions
(no symbols are exposed). Remove this file after the SDK is actually used in integration tasks.
*/

import _ "github.com/allanpk716/ai-agent-cli-rules/sdks/go"
