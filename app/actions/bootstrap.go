package actions

import (
	"context"

	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/pkg/i18n"
	"github.com/getfider/fider/app/pkg/validate"
)

// BootstrapTenant is the input model used by the internal bootstrap API to
// create or reconcile a tenant. Authentication is handled by the BootstrapAuth
// middleware, so IsAuthorized always returns true.
type BootstrapTenant struct {
	Name                string `json:"name"`
	Subdomain           string `json:"subdomain" format:"lower"`
	CNAME               string `json:"cname" format:"lower"`
	AdminName           string `json:"adminName"`
	AdminEmail          string `json:"adminEmail" format:"lower"`
	Locale              string `json:"locale"`
	Invitation          string `json:"invitation"`
	WelcomeHeader       string `json:"welcomeHeader"`
	WelcomeMessage      string `json:"welcomeMessage"`
	IsPrivate           bool   `json:"isPrivate"`
	IsEmailAuthAllowed  bool   `json:"isEmailAuthAllowed"`
	IsFeedEnabled       bool   `json:"isFeedEnabled"`
	IsModerationEnabled bool   `json:"isModerationEnabled"`
	RegenerateAPIKey    bool   `json:"regenerateApiKey"`
}

// IsAuthorized returns true — the bootstrap endpoint is protected by the
// BootstrapAuth middleware (instance-wide bootstrap token), not by user role.
func (action *BootstrapTenant) IsAuthorized(ctx context.Context, user *entity.User) bool {
	return true
}

// Validate if current model is valid. Subdomain and CNAME availability are
// validated in the handler (conditionally) so that re-applying an existing
// tenant stays idempotent.
func (action *BootstrapTenant) Validate(ctx context.Context, user *entity.User) *validate.Result {
	result := validate.Success()

	if action.Name == "" {
		result.AddFieldFailure("name", "Name is required.")
	}
	if len(action.Name) > 60 {
		result.AddFieldFailure("name", "Name must have less than 60 characters.")
	}

	if action.Subdomain == "" {
		result.AddFieldFailure("subdomain", "Subdomain is required.")
	}

	if action.AdminName == "" {
		result.AddFieldFailure("adminName", "Admin name is required.")
	}

	if action.AdminEmail == "" {
		result.AddFieldFailure("adminEmail", "Admin email is required.")
	} else {
		messages := validate.Email(ctx, action.AdminEmail)
		result.AddFieldFailure("adminEmail", messages...)
	}

	if action.Locale != "" && !i18n.IsValidLocale(action.Locale) {
		result.AddFieldFailure("locale", "Locale is invalid.")
	}

	if len(action.WelcomeHeader) > 100 {
		result.AddFieldFailure("welcomeHeader", "Welcome Header must have less than 100 characters.")
	}

	if action.IsPrivate && action.IsFeedEnabled {
		result.AddFieldFailure("isFeedEnabled", "Feed can not be enabled when set to private.")
	}

	return result
}
