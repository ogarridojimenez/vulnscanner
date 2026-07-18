package ldapauth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrConnection = errors.New("ldap connection failed")
	ErrAuth       = errors.New("ldap authentication failed")
	ErrNotFound   = errors.New("user not found")
)

type Config struct {
	URL        string
	BaseDN     string
	BindDN     string
	BindPass   string
	UserFilter string // e.g. "(uid=%s)"
	StartTLS   bool
	AdminGroup string // DN of admin group (e.g. "cn=vulnscanner-admins,ou=groups,dc=example,dc=com")
}

type Client struct {
	config Config
}

func New(cfg Config) *Client {
	return &Client{config: cfg}
}

type AuthResult struct {
	DisplayName string
	Email       string
	Role        string
}

func (c *Client) Authenticate(username, password string) (*AuthResult, error) {
	conn, err := ldap.DialURL(c.config.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnection, err)
	}
	defer conn.Close()

	if c.config.StartTLS {
		if err := conn.StartTLS(nil); err != nil {
			return nil, fmt.Errorf("startTLS: %w", err)
		}
	}

	// Bind as service account
	if c.config.BindDN != "" {
		if err := conn.Bind(c.config.BindDN, c.config.BindPass); err != nil {
			return nil, fmt.Errorf("bind service account: %w", err)
		}
	}

	// Search for user
	filter := fmt.Sprintf(c.config.UserFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn", "cn", "mail", "memberOf"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, ErrNotFound
	}

	// Bind as user
	userDN := result.Entries[0].DN
	if err := conn.Bind(userDN, password); err != nil {
		return nil, ErrAuth
	}

	// Extract attributes
	displayName := result.Entries[0].GetAttributeValue("cn")
	email := result.Entries[0].GetAttributeValue("mail")
	if displayName == "" {
		displayName = username
	}

	// Determine role from group membership
	role := "user"
	if c.config.AdminGroup != "" {
		for _, attr := range result.Entries[0].GetAttributeValues("memberOf") {
			if strings.EqualFold(attr, c.config.AdminGroup) {
				role = "admin"
				break
			}
		}
	}

	return &AuthResult{
		DisplayName: displayName,
		Email:       email,
		Role:        role,
	}, nil
}
