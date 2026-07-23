package middlewares

import (
	"crypto/subtle"
	"strings"

	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/web"
)

// BootstrapAuth protects the internal bootstrap API. It requires a valid
// `Authorization: Bearer <BOOTSTRAP_TOKEN>` header. When BOOTSTRAP_TOKEN is not
// configured the endpoint behaves as if it does not exist (404), so that the
// feature is disabled by default and its presence is not advertised.
func BootstrapAuth() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			expected := env.Config.BootstrapToken
			if expected == "" {
				return c.NotFound()
			}

			header := c.Request.GetHeader("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(header, prefix) {
				return c.Unauthorized()
			}

			provided := strings.TrimPrefix(header, prefix)
			if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
				return c.Unauthorized()
			}

			return next(c)
		}
	}
}
