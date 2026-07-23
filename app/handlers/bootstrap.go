package handlers

import (
	"strings"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/actions"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/validate"
	"github.com/getfider/fider/app/pkg/web"
)

// bootstrapTenantResponse is the payload returned by the bootstrap endpoints.
// It carries everything Terraform needs to wire up downstream resources
// (Keycloak clients, Fider OAuth config) in a single apply.
type bootstrapTenantResponse struct {
	ID          int               `json:"id"`
	Name        string            `json:"name"`
	Subdomain   string            `json:"subdomain"`
	Status      enum.TenantStatus `json:"status"`
	CNAME       string            `json:"cname"`
	PublicURL   string            `json:"publicUrl"`
	InternalURL string            `json:"internalUrl"`
	AdminUserID int               `json:"adminUserId"`
	APIKey      string            `json:"apiKey"`
}

// findTenantBySubdomain resolves a tenant by subdomain (or cname). Returns nil
// without error when no tenant matches.
func findTenantBySubdomain(c *web.Context, subdomain string) (*entity.Tenant, error) {
	byDomain := &query.GetTenantByDomain{Domain: subdomain}
	err := bus.Dispatch(c, byDomain)
	if err != nil {
		if errors.Cause(err) == app.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return byDomain.Result, nil
}

// tenantInternalURL builds the instance-internal URL for a tenant
// (e.g. https://acme.internal.example.com).
func tenantInternalURL(tenant *entity.Tenant) string {
	domain := env.MultiTenantDomain()
	if domain != "" {
		return "https://" + tenant.Subdomain + domain
	}
	return strings.TrimRight(env.Config.BaseURL, "/")
}

// tenantPublicURL returns the public URL of a tenant: its custom domain when
// set, otherwise the internal URL.
func tenantPublicURL(tenant *entity.Tenant) string {
	if tenant.CNAME != "" {
		return "https://" + tenant.CNAME
	}
	return tenantInternalURL(tenant)
}

// BootstrapTenant creates or reconciles a tenant without going through the
// signup UI or email verification. It is idempotent: re-applying the same input
// leaves the tenant, its admin user, and the API key unchanged.
func BootstrapTenant() web.HandlerFunc {
	return func(c *web.Context) error {
		action := new(actions.BootstrapTenant)
		if result := c.BindTo(action); !result.Ok {
			return c.HandleValidation(result)
		}

		tenant, err := findTenantBySubdomain(c, action.Subdomain)
		if err != nil {
			return c.Failure(err)
		}

		if tenant == nil {
			// Creating a new tenant. In single-host mode only one tenant may exist.
			if env.IsSingleHostMode() {
				first := &query.GetFirstTenant{}
				if err := bus.Dispatch(c, first); err != nil && errors.Cause(err) != app.ErrNotFound {
					return c.Failure(err)
				}
				if first.Result != nil {
					return c.BadRequest(web.Map{
						"message": "A tenant already exists. Single-host mode supports only one tenant.",
					})
				}
			}

			if messages, err := validate.Subdomain(c, action.Subdomain); err != nil {
				return c.Failure(err)
			} else if len(messages) > 0 {
				return c.BadRequest(web.Map{"message": strings.Join(messages, ", ")})
			}

			createTenant := &cmd.CreateTenant{
				Name:      action.Name,
				Subdomain: action.Subdomain,
				Status:    enum.TenantActive,
			}
			if err := bus.Dispatch(c, createTenant); err != nil {
				return c.Failure(err)
			}
			tenant = createTenant.Result
		}

		c.SetTenant(tenant)

		// Activate the tenant if it was pending/locked/disabled.
		if tenant.Status != enum.TenantActive {
			if err := bus.Dispatch(c, &cmd.UpdateTenantStatus{TenantID: tenant.ID, Status: enum.TenantActive}); err != nil {
				return c.Failure(err)
			}
			tenant.Status = enum.TenantActive
		}

		// Validate CNAME only when it changes, so re-applying the same value
		// (which is "taken" by this very tenant) stays idempotent.
		if action.CNAME != "" && action.CNAME != tenant.CNAME {
			if messages := validate.CNAME(c, action.CNAME); len(messages) > 0 {
				return c.BadRequest(web.Map{"message": strings.Join(messages, ", ")})
			}
		}

		locale := action.Locale
		if locale == "" {
			locale = tenant.Locale
		}

		if err := bus.Dispatch(c, &cmd.UpdateTenantSettings{
			Title:          action.Name,
			Invitation:     action.Invitation,
			WelcomeMessage: action.WelcomeMessage,
			WelcomeHeader:  action.WelcomeHeader,
			CNAME:          action.CNAME,
			Locale:         locale,
		}); err != nil {
			return c.Failure(err)
		}

		if err := bus.Dispatch(c, &cmd.UpdateTenantPrivacySettings{
			IsPrivate:           action.IsPrivate,
			IsFeedEnabled:       action.IsFeedEnabled,
			IsModerationEnabled: action.IsModerationEnabled,
		}); err != nil {
			return c.Failure(err)
		}

		if err := bus.Dispatch(c, &cmd.UpdateTenantEmailAuthAllowedSettings{
			IsEmailAuthAllowed: action.IsEmailAuthAllowed,
		}); err != nil {
			return c.Failure(err)
		}

		// Refresh the tenant so the response reflects the persisted settings.
		tenant, err = findTenantBySubdomain(c, action.Subdomain)
		if err != nil {
			return c.Failure(err)
		}
		c.SetTenant(tenant)

		admin, err := reconcileAdminUser(c, action.AdminName, action.AdminEmail)
		if err != nil {
			return c.Failure(err)
		}

		ensureKey := &cmd.EnsureAPIKey{UserID: admin.ID, Regenerate: action.RegenerateAPIKey}
		if err := bus.Dispatch(c, ensureKey); err != nil {
			return c.Failure(err)
		}

		return c.Ok(buildTenantResponse(tenant, admin.ID, ensureKey.Result))
	}
}

// reconcileAdminUser ensures an active administrator with the given email
// exists for the current tenant, creating it or promoting an existing user.
func reconcileAdminUser(c *web.Context, name, email string) (*entity.User, error) {
	byEmail := &query.GetUserByEmail{Email: email}
	err := bus.Dispatch(c, byEmail)
	if err != nil && errors.Cause(err) != app.ErrNotFound {
		return nil, err
	}

	if byEmail.Result == nil {
		user := &entity.User{
			Name:   name,
			Email:  email,
			Tenant: c.Tenant(),
			Role:   enum.RoleAdministrator,
		}
		if err := bus.Dispatch(c, &cmd.RegisterUser{User: user}); err != nil {
			return nil, err
		}
		return user, nil
	}

	user := byEmail.Result
	if user.Role != enum.RoleAdministrator {
		if err := bus.Dispatch(c, &cmd.ChangeUserRole{UserID: user.ID, Role: enum.RoleAdministrator}); err != nil {
			return nil, err
		}
		user.Role = enum.RoleAdministrator
	}
	return user, nil
}

func buildTenantResponse(tenant *entity.Tenant, adminUserID int, apiKey string) *bootstrapTenantResponse {
	return &bootstrapTenantResponse{
		ID:          tenant.ID,
		Name:        tenant.Name,
		Subdomain:   tenant.Subdomain,
		Status:      tenant.Status,
		CNAME:       tenant.CNAME,
		PublicURL:   tenantPublicURL(tenant),
		InternalURL: tenantInternalURL(tenant),
		AdminUserID: adminUserID,
		APIKey:      apiKey,
	}
}

// GetBootstrapTenant reads the current state of a tenant by subdomain. Used by
// the Terraform provider's Read to detect drift. Returns 404 when the tenant
// does not exist so Terraform can recreate it.
func GetBootstrapTenant() web.HandlerFunc {
	return func(c *web.Context) error {
		tenant, err := findTenantBySubdomain(c, c.Param("subdomain"))
		if err != nil {
			return c.Failure(err)
		}
		if tenant == nil {
			return c.NotFound()
		}

		c.SetTenant(tenant)

		admin := &query.GetUserByEmail{Email: c.QueryParam("adminEmail")}
		adminUserID := 0
		apiKey := ""
		if c.QueryParam("adminEmail") != "" {
			if err := bus.Dispatch(c, admin); err != nil && errors.Cause(err) != app.ErrNotFound {
				return c.Failure(err)
			}
			if admin.Result != nil {
				adminUserID = admin.Result.ID
				key := &query.GetUserAPIKey{UserID: admin.Result.ID}
				if err := bus.Dispatch(c, key); err != nil {
					return c.Failure(err)
				}
				apiKey = key.Result
			}
		}

		return c.Ok(buildTenantResponse(tenant, adminUserID, apiKey))
	}
}

// BootstrapLockTenant sets a tenant to the locked (read-only) status. Used by
// the Terraform provider's Delete, since Fider has no tenant-delete API.
func BootstrapLockTenant() web.HandlerFunc {
	return func(c *web.Context) error {
		tenant, err := findTenantBySubdomain(c, c.Param("subdomain"))
		if err != nil {
			return c.Failure(err)
		}
		if tenant == nil {
			return c.NotFound()
		}

		c.SetTenant(tenant)
		if err := bus.Dispatch(c, &cmd.UpdateTenantStatus{TenantID: tenant.ID, Status: enum.TenantLocked}); err != nil {
			return c.Failure(err)
		}

		return c.Ok(web.Map{"id": tenant.ID, "status": enum.TenantLocked})
	}
}

// BootstrapOAuthConfig manages a tenant's custom OAuth provider config through
// the bootstrap token, addressed by subdomain. It resolves the tenant, grants a
// synthetic admin context, and delegates to the existing admin OAuth handler so
// all validation and persistence logic is shared.
func BootstrapOAuthConfig() web.HandlerFunc {
	save := SaveOAuthConfig()
	return func(c *web.Context) error {
		if err := withBootstrapAdminContext(c); err != nil {
			return c.Failure(err)
		}
		if c.Tenant() == nil {
			return c.NotFound()
		}
		return save(c)
	}
}

// GetBootstrapOAuthConfig reads a tenant's custom OAuth config by subdomain.
func GetBootstrapOAuthConfig() web.HandlerFunc {
	get := GetOAuthConfig()
	return func(c *web.Context) error {
		if err := withBootstrapAdminContext(c); err != nil {
			return c.Failure(err)
		}
		if c.Tenant() == nil {
			return c.NotFound()
		}
		return get(c)
	}
}

// withBootstrapAdminContext resolves the tenant named by the :subdomain route
// param and sets a synthetic administrator on the context, so that handlers
// guarded by an admin-role check can be reused under bootstrap-token auth.
func withBootstrapAdminContext(c *web.Context) error {
	tenant, err := findTenantBySubdomain(c, c.Param("subdomain"))
	if err != nil {
		return err
	}
	if tenant == nil {
		return nil
	}
	c.SetTenant(tenant)
	c.SetUser(&entity.User{
		Tenant: tenant,
		Role:   enum.RoleAdministrator,
		Status: enum.UserActive,
	})
	return nil
}
