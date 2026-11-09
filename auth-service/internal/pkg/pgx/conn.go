package pgx

import (
	"fmt"
	"strings"
)

func BuildConnString(
	user, password, host string,
	port int, name string, options ...string,
) string {
	base := fmt.Sprintf(
		"postgresql://%s:%s@%s:%d/%s?",
		user, password, host, port, name,
	)

	var sb strings.Builder
	for _, option := range options {
		sb.WriteString(option)
		sb.WriteByte('&')
	}

	return base + sb.String()[:sb.Len()-1]
}

