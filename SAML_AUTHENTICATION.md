# SAML 2.0 Authentication for Cellxgene Gateway

This document describes the SAML 2.0 authentication implementation added to Cellxgene Gateway.

## Overview

SAML 2.0 (Security Assertion Markup Language) support has been added to enable Single Sign-On (SSO) authentication with enterprise Identity Providers (IdPs). This allows organizations to:

- Centralize authentication through their existing IdP (Okta, Azure AD, Google Workspace, etc.)
- Enforce organizational security policies
- Manage user access centrally
- Support Single Logout (SLO) for enhanced security

## Features

- **Full SAML 2.0 SP (Service Provider) implementation**
- **SSO (Single Sign-On)**: Users authenticate via their organization's IdP
- **SLO (Single Logout)**: Proper logout handling with IdP
- **Flexible configuration**: Environment variables or JSON file
- **Attribute mapping**: Customize how IdP attributes map to user fields
- **Optional authentication**: Can be enabled/disabled, required or optional
- **Session management**: Secure session handling with Flask
- **Backward compatible**: Works alongside existing authentication methods

## Architecture

### Components

1. **saml_auth.py**: Core SAML functionality
   - `SAMLConfig`: Configuration management
   - `init_saml_auth()`: Initialize SAML authentication
   - `extract_user_attributes()`: Process SAML assertions
   - Helper functions for SAML operations

2. **gateway.py**: SAML routes and integration
   - `/saml/login`: Initiate SSO
   - `/saml/acs`: Assertion Consumer Service (processes IdP response)
   - `/saml/metadata`: SP metadata endpoint
   - `/saml/logout`: Initiate SLO
   - `/saml/sls`: Single Logout Service
   - Session management and authentication checks

3. **env.py**: Configuration variables
   - SAML-related environment variables
   - Feature flags and settings

4. **ItemSource implementations**: Authorization checks
   - Updated `is_authorized()` methods in FileItemSource and S3ItemSource
   - Check SAML session when authentication is required

## Installation

### 1. Install Dependencies

```bash
pip install python3-saml
```

Or update from requirements.txt:
```bash
pip install -r requirements.txt
```

### 2. Configure SAML

Choose one of two configuration methods:

#### Option A: Environment Variables (Simpler)

```bash
# Enable SAML
export SAML_ENABLED=true

# Service Provider settings
export SAML_SP_ENTITY_ID="cellxgene-gateway"
export SAML_SP_ACS_URL="https://your-domain.com/saml/acs"
export SAML_SP_SLS_URL="https://your-domain.com/saml/sls"

# Identity Provider settings (get these from your IdP)
export SAML_IDP_ENTITY_ID="https://idp.example.com/entityid"
export SAML_IDP_SSO_URL="https://idp.example.com/sso"
export SAML_IDP_SLO_URL="https://idp.example.com/slo"
export SAML_IDP_X509_CERT="MIIDXTCCAkWgAwIBAgIJ..."  # Full certificate

# Require authentication for all access (optional, default: false)
export SAML_REQUIRE_AUTHENTICATION=true

# Flask session secret (required)
export FLASK_SECRET_KEY="generate-a-secure-random-string-here"
```

#### Option B: JSON Configuration File (Advanced)

```bash
# Point to configuration file
export SAML_SETTINGS_PATH="/path/to/saml_config/settings.json"
export SAML_ENABLED=true
export SAML_REQUIRE_AUTHENTICATION=true
export FLASK_SECRET_KEY="generate-a-secure-random-string-here"
```

See `saml_config/settings.json.example` for the file format.

### 3. Register with Your IdP

1. Get your SP metadata:
   ```
   https://your-domain.com/saml/metadata
   ```

2. Provide this metadata to your IdP administrator

3. Configure attribute mappings in your IdP to match what's expected:
   - `uid` or custom username attribute
   - `email`
   - `givenName` (optional)
   - `sn` (surname, optional)

### 4. Test the Integration

1. Start the gateway
2. Visit `/saml/login`
3. You should be redirected to your IdP
4. After authentication, you'll return to the gateway

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SAML_ENABLED` | No | false | Enable SAML authentication |
| `SAML_SETTINGS_PATH` | No | - | Path to JSON settings file |
| `SAML_SP_ENTITY_ID` | No | cellxgene-gateway | Service Provider entity ID |
| `SAML_SP_ACS_URL` | Yes* | - | Assertion Consumer Service URL |
| `SAML_SP_SLS_URL` | No | - | Single Logout Service URL |
| `SAML_IDP_ENTITY_ID` | Yes* | - | Identity Provider entity ID |
| `SAML_IDP_SSO_URL` | Yes* | - | IdP Single Sign-On URL |
| `SAML_IDP_SLO_URL` | No | - | IdP Single Logout URL |
| `SAML_IDP_X509_CERT` | Yes* | - | IdP X.509 certificate |
| `SAML_REQUIRE_AUTHENTICATION` | No | false | Require auth for all access |
| `FLASK_SECRET_KEY` | Yes | - | Session encryption key |
| `SAML_SP_X509_CERT` | No | - | SP certificate (for signing) |
| `SAML_SP_PRIVATE_KEY` | No | - | SP private key (for signing) |
| `SAML_WANT_ASSERTIONS_SIGNED` | No | true | Require signed assertions |
| `SAML_WANT_MESSAGES_SIGNED` | No | false | Require signed messages |
| `SAML_SIGN_AUTHN_REQUEST` | No | false | Sign authentication requests |
| `SAML_ATTR_USERNAME` | No | uid | Username attribute name |
| `SAML_ATTR_EMAIL` | No | email | Email attribute name |
| `SAML_ATTR_FIRST_NAME` | No | givenName | First name attribute |
| `SAML_ATTR_LAST_NAME` | No | sn | Last name attribute |
| `SAML_DEBUG` | No | false | Enable debug logging |

\* Required when using environment variable configuration

### Generating Flask Secret Key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## Usage

### Protected Routes

When `SAML_REQUIRE_AUTHENTICATION=true`, all data access requires authentication:
- Unauthenticated users are redirected to `/saml/login`
- After successful authentication, they're redirected to their original destination
- Sessions persist across requests

### Optional Authentication

When `SAML_REQUIRE_AUTHENTICATION=false`:
- SAML authentication is available but not required
- Useful for mixed environments or gradual rollout
- Backward compatible with existing deployments

### User Session

Authenticated users have a session containing:
```python
{
    'saml_user': {
        'nameid': 'user@example.com',
        'username': 'user123',
        'email': 'user@example.com',
        'first_name': 'John',
        'last_name': 'Doe',
        'session_index': 'SAMLSessionIndex',
        'attributes': {...}  # All SAML attributes
    },
    'saml_authenticated': True
}
```

### Logout

Users can logout at `/saml/logout`:
- Clears local session
- Initiates SLO with IdP (if configured)
- Redirects to homepage or IdP logout page

## Security Considerations

### Production Requirements

1. **Always use HTTPS**: SAML requires secure transport
   ```bash
   export EXTERNAL_PROTOCOL=https
   ```

2. **Strong session secret**: Generate and secure `FLASK_SECRET_KEY`
   ```bash
   # Generate
   python3 -c "import secrets; print(secrets.token_hex(32))"
   
   # Store securely (don't commit to git)
   export FLASK_SECRET_KEY="your-generated-key"
   ```

3. **Validate signatures**: Keep `SAML_WANT_ASSERTIONS_SIGNED=true`

4. **Secure certificate storage**: If using SP signing:
   - Keep `sp.key` private (never commit to version control)
   - Use appropriate file permissions (600 or 400)
   - Rotate certificates periodically

5. **IdP certificate validation**: Ensure correct IdP certificate is configured

### Session Configuration

Sessions are configured with:
- `SESSION_COOKIE_SECURE`: Enabled when using HTTPS
- `SESSION_COOKIE_HTTPONLY`: Always enabled (prevents XSS)
- `SESSION_COOKIE_SAMESITE`: Set to 'Lax' (prevents CSRF)

### Proxy Configuration

If behind a reverse proxy, configure proxy headers:
```bash
export PROXY_FIX_FOR=1
export PROXY_FIX_PROTO=1
export PROXY_FIX_HOST=1
export PROXY_FIX_PORT=1
```

## Common IdP Configurations

### Okta

```bash
export SAML_IDP_ENTITY_ID="http://www.okta.com/exk..."
export SAML_IDP_SSO_URL="https://your-org.okta.com/app/your-app/exk.../sso/saml"
export SAML_IDP_X509_CERT="MIIDp..."
export SAML_ATTR_USERNAME="username"
export SAML_ATTR_EMAIL="email"
```

### Azure AD

```bash
export SAML_IDP_ENTITY_ID="https://sts.windows.net/tenant-id/"
export SAML_IDP_SSO_URL="https://login.microsoftonline.com/tenant-id/saml2"
export SAML_IDP_X509_CERT="MIIDp..."
export SAML_ATTR_USERNAME="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
export SAML_ATTR_EMAIL="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
```

### Google Workspace

```bash
export SAML_IDP_ENTITY_ID="https://accounts.google.com/o/saml2?idpid=..."
export SAML_IDP_SSO_URL="https://accounts.google.com/o/saml2/idp?idpid=..."
export SAML_IDP_X509_CERT="MIIDd..."
export SAML_ATTR_USERNAME="username"
export SAML_ATTR_EMAIL="email"
```

## Troubleshooting

### Enable Debug Mode

```bash
export SAML_DEBUG=true
export GATEWAY_LOG_LEVEL=DEBUG
```

### Common Issues

1. **"SAML authentication is not enabled" error**
   - Solution: Set `SAML_ENABLED=true`

2. **Redirect loop after IdP authentication**
   - Check that `SAML_SP_ACS_URL` matches the registered URL in IdP
   - Verify proxy configuration if behind reverse proxy

3. **"SAML authentication failed" error**
   - Verify IdP certificate matches configuration
   - Check IdP logs for errors
   - Enable debug mode for detailed error messages

4. **Attribute mapping issues**
   - Check IdP attribute names vs. configured mapping
   - Enable debug mode to see received attributes
   - Update `SAML_ATTR_*` variables to match IdP

5. **Session not persisting**
   - Verify `FLASK_SECRET_KEY` is set and consistent
   - Check cookie settings (secure flag requires HTTPS)
   - Verify proxy headers are configured correctly

### Testing Without IdP

For development/testing without a real IdP:
1. Use a SAML test IdP like https://samltest.id
2. Or set `SAML_REQUIRE_AUTHENTICATION=false` to make auth optional

## Migration Guide

### Existing Deployments

SAML is fully backward compatible. To migrate:

1. **Install dependencies**: `pip install python3-saml`

2. **Optional authentication first**:
   ```bash
   export SAML_ENABLED=true
   export SAML_REQUIRE_AUTHENTICATION=false
   # ... other SAML config
   ```

3. **Test authentication**: Verify users can authenticate via `/saml/login`

4. **Enable required authentication**:
   ```bash
   export SAML_REQUIRE_AUTHENTICATION=true
   ```

5. **Monitor and adjust**: Check logs, adjust configuration as needed

## API Reference

### Routes

- `GET /saml/login` - Initiate SSO
- `POST /saml/acs` - Assertion Consumer Service (callback from IdP)
- `GET /saml/metadata` - SP metadata XML
- `GET /saml/logout` - Initiate logout
- `GET|POST /saml/sls` - Single Logout Service (callback from IdP)

### Helper Functions

```python
# Get current authenticated user
from cellxgene_gateway.gateway import get_current_user
user = get_current_user()  # Returns dict or None

# Check if SAML is enabled
from cellxgene_gateway.saml_auth import is_saml_enabled
if is_saml_enabled():
    # SAML is configured
```

### Decorators

```python
# Require SAML authentication for a route
from cellxgene_gateway.gateway import require_saml_auth

@app.route("/protected")
@require_saml_auth
def protected_view():
    # Only accessible to authenticated users
    pass
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run SAML-specific tests (if added)
pytest tests/test_saml_auth.py
```

### Adding Custom Authorization Logic

Extend `is_authorized()` in ItemSource implementations:

```python
def is_authorized(self, descriptor):
    # Check SAML authentication
    from cellxgene_gateway import env
    if env.saml_enabled and env.saml_require_authentication:
        from flask import session
        if not session.get('saml_authenticated', False):
            return False
        
        # Add custom logic here
        user = session.get('saml_user', {})
        # Example: check user group membership
        if 'admin' in user.get('attributes', {}).get('groups', []):
            return True
    
    return True
```

## Support

For issues or questions:
1. Check logs with `GATEWAY_LOG_LEVEL=DEBUG`
2. Review this documentation
3. Consult your IdP documentation
4. Open an issue on GitHub

## License

This SAML implementation follows the same license as Cellxgene Gateway (Apache 2.0).
