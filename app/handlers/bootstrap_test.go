package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/handlers"
	"github.com/getfider/fider/app/middlewares"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/mock"
)

// bootstrapStore is a stateful, in-memory fake of the bus handlers the
// bootstrap endpoint relies on, so idempotency can be exercised for real.
type bootstrapStore struct {
	tenants   map[string]*entity.Tenant // keyed by subdomain
	users     map[string]*entity.User   // keyed by "tenantID|email"
	apiKeys   map[int]string            // keyed by userID
	nextTenID int
	nextUsrID int
	keySeq    int
}

func userKey(tenantID int, email string) string {
	return fmt.Sprintf("%d|%s", tenantID, email)
}

func tenantFromCtx(ctx context.Context) *entity.Tenant {
	t, _ := ctx.Value(app.TenantCtxKey).(*entity.Tenant)
	return t
}

func setupBootstrapStore() *bootstrapStore {
	s := &bootstrapStore{
		tenants:   map[string]*entity.Tenant{},
		users:     map[string]*entity.User{},
		apiKeys:   map[int]string{},
		nextTenID: 100,
		nextUsrID: 500,
	}

	bus.AddHandler(func(ctx context.Context, q *query.GetTenantByDomain) error {
		if t, ok := s.tenants[q.Domain]; ok {
			q.Result = t
			return nil
		}
		for _, t := range s.tenants {
			if t.CNAME != "" && t.CNAME == q.Domain {
				q.Result = t
				return nil
			}
		}
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetFirstTenant) error {
		for _, t := range s.tenants {
			q.Result = t
			return nil
		}
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.IsSubdomainAvailable) error {
		_, taken := s.tenants[q.Subdomain]
		q.Result = !taken
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.IsCNAMEAvailable) error {
		for _, t := range s.tenants {
			if t.CNAME == q.CNAME {
				q.Result = false
				return nil
			}
		}
		q.Result = true
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.CreateTenant) error {
		s.nextTenID++
		t := &entity.Tenant{
			ID:        s.nextTenID,
			Name:      c.Name,
			Subdomain: c.Subdomain,
			Status:    c.Status,
		}
		s.tenants[c.Subdomain] = t
		c.Result = t
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateTenantStatus) error {
		for _, t := range s.tenants {
			if t.ID == c.TenantID {
				t.Status = c.Status
			}
		}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateTenantSettings) error {
		t := tenantFromCtx(ctx)
		if t == nil {
			return fmt.Errorf("no tenant in context")
		}
		t.Name = c.Title
		t.Invitation = c.Invitation
		t.WelcomeMessage = c.WelcomeMessage
		t.WelcomeHeader = c.WelcomeHeader
		t.CNAME = c.CNAME
		t.Locale = c.Locale
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateTenantPrivacySettings) error {
		t := tenantFromCtx(ctx)
		t.IsPrivate = c.IsPrivate
		t.IsFeedEnabled = c.IsFeedEnabled
		t.IsModerationEnabled = c.IsModerationEnabled
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateTenantEmailAuthAllowedSettings) error {
		t := tenantFromCtx(ctx)
		t.IsEmailAuthAllowed = c.IsEmailAuthAllowed
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		t := tenantFromCtx(ctx)
		if t == nil {
			return app.ErrNotFound
		}
		if u, ok := s.users[userKey(t.ID, q.Email)]; ok {
			q.Result = u
			return nil
		}
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUser) error {
		t := tenantFromCtx(ctx)
		s.nextUsrID++
		c.User.ID = s.nextUsrID
		c.User.Status = enum.UserActive
		s.users[userKey(t.ID, c.User.Email)] = c.User
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.ChangeUserRole) error {
		for _, u := range s.users {
			if u.ID == c.UserID {
				u.Role = c.Role
			}
		}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserAPIKey) error {
		q.Result = s.apiKeys[q.UserID]
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.EnsureAPIKey) error {
		existing := s.apiKeys[c.UserID]
		if existing != "" && !c.Regenerate {
			c.Result = existing
			return nil
		}
		s.keySeq++
		key := fmt.Sprintf("apikey-%d-%d", c.UserID, s.keySeq)
		s.apiKeys[c.UserID] = key
		c.Result = key
		return nil
	})

	return s
}

const acmeBody = `{
	"name": "Acme",
	"subdomain": "acme",
	"cname": "feedback.acme.com",
	"adminName": "Alice",
	"adminEmail": "alice@acme.com",
	"locale": "en",
	"isEmailAuthAllowed": true,
	"isFeedEnabled": true
}`

func TestBootstrapTenant_Unauthorized_NoToken(t *testing.T) {
	RegisterT(t)
	defer func(v string) { env.Config.BootstrapToken = v }(env.Config.BootstrapToken)
	env.Config.BootstrapToken = "s3cret"

	server := mock.NewServer()
	code, _ := server.
		Use(middlewares.BootstrapAuth()).
		ExecutePost(handlers.BootstrapTenant(), acmeBody)

	Expect(code).Equals(http.StatusUnauthorized)
}

func TestBootstrapTenant_Unauthorized_BadToken(t *testing.T) {
	RegisterT(t)
	defer func(v string) { env.Config.BootstrapToken = v }(env.Config.BootstrapToken)
	env.Config.BootstrapToken = "s3cret"

	server := mock.NewServer()
	code, _ := server.
		Use(middlewares.BootstrapAuth()).
		AddHeader("Authorization", "Bearer wrong").
		ExecutePost(handlers.BootstrapTenant(), acmeBody)

	Expect(code).Equals(http.StatusUnauthorized)
}

func TestBootstrapTenant_Disabled_WhenTokenUnset(t *testing.T) {
	RegisterT(t)
	defer func(v string) { env.Config.BootstrapToken = v }(env.Config.BootstrapToken)
	env.Config.BootstrapToken = ""

	server := mock.NewServer()
	code, _ := server.
		Use(middlewares.BootstrapAuth()).
		AddHeader("Authorization", "Bearer anything").
		ExecutePost(handlers.BootstrapTenant(), acmeBody)

	Expect(code).Equals(http.StatusNotFound)
}

func TestBootstrapTenant_Authorized_ValidToken(t *testing.T) {
	RegisterT(t)
	setupBootstrapStore()
	defer func(v string) { env.Config.BootstrapToken = v }(env.Config.BootstrapToken)
	env.Config.BootstrapToken = "s3cret"

	server := mock.NewServer()
	code, _ := server.
		Use(middlewares.BootstrapAuth()).
		AddHeader("Authorization", "Bearer s3cret").
		ExecutePost(handlers.BootstrapTenant(), acmeBody)

	Expect(code).Equals(http.StatusOK)
}

func TestBootstrapTenant_Create(t *testing.T) {
	RegisterT(t)
	store := setupBootstrapStore()
	defer func(v string) { env.Config.HostDomain = v }(env.Config.HostDomain)
	env.Config.HostDomain = "internal.example.com"

	server := mock.NewServer()
	code, response := server.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)

	Expect(code).Equals(http.StatusOK)
	Expect(response.Int32("id")).NotEquals(0)
	Expect(response.String("subdomain")).Equals("acme")
	Expect(response.String("cname")).Equals("feedback.acme.com")
	Expect(response.String("publicUrl")).Equals("https://feedback.acme.com")
	Expect(response.String("internalUrl")).Equals("https://acme.internal.example.com")
	Expect(response.String("apiKey")).IsNotEmpty()
	Expect(response.Int32("adminUserId")).NotEquals(0)

	created := store.tenants["acme"]
	Expect(created).IsNotNil()
	Expect(created.Status).Equals(enum.TenantActive)
	Expect(created.IsEmailAuthAllowed).IsTrue()

	admin := store.users[userKey(created.ID, "alice@acme.com")]
	Expect(admin).IsNotNil()
	Expect(admin.Role).Equals(enum.RoleAdministrator)
}

func TestBootstrapTenant_Idempotent(t *testing.T) {
	RegisterT(t)
	setupBootstrapStore()

	server := mock.NewServer()
	code, first := server.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)
	Expect(code).Equals(http.StatusOK)

	server2 := mock.NewServer()
	code2, second := server2.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)
	Expect(code2).Equals(http.StatusOK)

	Expect(second.Int32("id")).Equals(first.Int32("id"))
	Expect(second.Int32("adminUserId")).Equals(first.Int32("adminUserId"))
	Expect(second.String("apiKey")).Equals(first.String("apiKey"))
}

func TestBootstrapTenant_UpdateCNAME(t *testing.T) {
	RegisterT(t)
	store := setupBootstrapStore()

	server := mock.NewServer()
	server.ExecutePost(handlers.BootstrapTenant(), acmeBody)

	updated := `{
		"name": "Acme",
		"subdomain": "acme",
		"cname": "support.acme.com",
		"adminName": "Alice",
		"adminEmail": "alice@acme.com",
		"isEmailAuthAllowed": true
	}`
	server2 := mock.NewServer()
	code, response := server2.ExecutePostAsJSON(handlers.BootstrapTenant(), updated)

	Expect(code).Equals(http.StatusOK)
	Expect(response.String("cname")).Equals("support.acme.com")
	Expect(store.tenants["acme"].CNAME).Equals("support.acme.com")
}

func TestBootstrapTenant_DuplicateCNAMEConflict(t *testing.T) {
	RegisterT(t)
	setupBootstrapStore()

	server := mock.NewServer()
	server.ExecutePost(handlers.BootstrapTenant(), acmeBody)

	// A different tenant trying to claim the same CNAME must fail.
	conflicting := `{
		"name": "Widgetco",
		"subdomain": "widgetco",
		"cname": "feedback.acme.com",
		"adminName": "Bob",
		"adminEmail": "bob@widgetco.com",
		"isEmailAuthAllowed": true
	}`
	server2 := mock.NewServer()
	code, _ := server2.ExecutePostAsJSON(handlers.BootstrapTenant(), conflicting)

	Expect(code).Equals(http.StatusBadRequest)
}

func TestBootstrapTenant_PromotesExistingUserToAdmin(t *testing.T) {
	RegisterT(t)
	store := setupBootstrapStore()

	// Pre-create the tenant and a non-admin user.
	tenant := &entity.Tenant{ID: 100, Name: "Acme", Subdomain: "acme", Status: enum.TenantActive}
	store.tenants["acme"] = tenant
	store.users[userKey(100, "alice@acme.com")] = &entity.User{
		ID: 7, Name: "Alice", Email: "alice@acme.com", Tenant: tenant, Role: enum.RoleVisitor, Status: enum.UserActive,
	}

	server := mock.NewServer()
	code, response := server.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)

	Expect(code).Equals(http.StatusOK)
	Expect(response.Int32("adminUserId")).Equals(7)
	Expect(store.users[userKey(100, "alice@acme.com")].Role).Equals(enum.RoleAdministrator)
}

func TestBootstrapTenant_RetainsExistingAdmin(t *testing.T) {
	RegisterT(t)
	store := setupBootstrapStore()

	tenant := &entity.Tenant{ID: 100, Name: "Acme", Subdomain: "acme", Status: enum.TenantActive}
	store.tenants["acme"] = tenant
	store.users[userKey(100, "alice@acme.com")] = &entity.User{
		ID: 7, Name: "Alice", Email: "alice@acme.com", Tenant: tenant, Role: enum.RoleAdministrator, Status: enum.UserActive,
	}

	server := mock.NewServer()
	code, response := server.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)

	Expect(code).Equals(http.StatusOK)
	Expect(response.Int32("adminUserId")).Equals(7)
	Expect(store.users[userKey(100, "alice@acme.com")].Role).Equals(enum.RoleAdministrator)
}

func TestBootstrapTenant_APIKeyStableAndRotatable(t *testing.T) {
	RegisterT(t)
	setupBootstrapStore()

	server := mock.NewServer()
	_, first := server.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)
	originalKey := first.String("apiKey")
	Expect(originalKey).IsNotEmpty()

	// Re-apply without regenerate -> same key.
	server2 := mock.NewServer()
	_, second := server2.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)
	Expect(second.String("apiKey")).Equals(originalKey)

	// Re-apply with regenerate -> new key.
	rotate := `{
		"name": "Acme",
		"subdomain": "acme",
		"cname": "feedback.acme.com",
		"adminName": "Alice",
		"adminEmail": "alice@acme.com",
		"isEmailAuthAllowed": true,
		"regenerateApiKey": true
	}`
	server3 := mock.NewServer()
	_, third := server3.ExecutePostAsJSON(handlers.BootstrapTenant(), rotate)
	Expect(third.String("apiKey")).NotEquals(originalKey)
}

func TestBootstrapTenant_MultiTenantIsolation(t *testing.T) {
	RegisterT(t)
	store := setupBootstrapStore()

	server := mock.NewServer()
	_, acme := server.ExecutePostAsJSON(handlers.BootstrapTenant(), acmeBody)

	rpBody := `{
		"name": "Widgetco",
		"subdomain": "widgetco",
		"cname": "feedback.widgetco.com",
		"adminName": "Bob",
		"adminEmail": "bob@widgetco.com",
		"isEmailAuthAllowed": true
	}`
	server2 := mock.NewServer()
	_, rp := server2.ExecutePostAsJSON(handlers.BootstrapTenant(), rpBody)

	Expect(rp.Int32("id")).NotEquals(acme.Int32("id"))
	Expect(store.tenants["acme"].CNAME).Equals("feedback.acme.com")
	Expect(store.tenants["widgetco"].CNAME).Equals("feedback.widgetco.com")
}

func TestBootstrapTenant_InvalidInput(t *testing.T) {
	RegisterT(t)
	setupBootstrapStore()

	server := mock.NewServer()
	code, _ := server.ExecutePost(handlers.BootstrapTenant(), `{ "subdomain": "x" }`)

	Expect(code).Equals(http.StatusBadRequest)
}

func TestGetBootstrapTenant_NotFound(t *testing.T) {
	RegisterT(t)
	setupBootstrapStore()

	server := mock.NewServer()
	code, _ := server.AddParam("subdomain", "missing").Execute(handlers.GetBootstrapTenant())

	Expect(code).Equals(http.StatusNotFound)
}

func TestGetBootstrapTenant_ReturnsState(t *testing.T) {
	RegisterT(t)
	setupBootstrapStore()

	create := mock.NewServer()
	create.ExecutePost(handlers.BootstrapTenant(), acmeBody)

	server := mock.NewServer()
	code, response := server.
		AddParam("subdomain", "acme").
		WithURL("http://acme.test.fider.io/_api/internal/bootstrap/tenant/acme?adminEmail=alice@acme.com").
		ExecuteAsJSON(handlers.GetBootstrapTenant())

	Expect(code).Equals(http.StatusOK)
	Expect(response.String("subdomain")).Equals("acme")
	Expect(response.String("apiKey")).IsNotEmpty()
	Expect(response.Int32("adminUserId")).NotEquals(0)
}

func TestBootstrapLockTenant(t *testing.T) {
	RegisterT(t)
	store := setupBootstrapStore()

	create := mock.NewServer()
	create.ExecutePost(handlers.BootstrapTenant(), acmeBody)

	server := mock.NewServer()
	code, _ := server.AddParam("subdomain", "acme").ExecutePost(handlers.BootstrapLockTenant(), `{}`)

	Expect(code).Equals(http.StatusOK)
	Expect(store.tenants["acme"].Status).Equals(enum.TenantLocked)
}
