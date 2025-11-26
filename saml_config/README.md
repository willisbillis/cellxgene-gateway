# SAML Configuration Directory

This directory contains SAML 2.0 authentication configuration files for Cellxgene Gateway.

## Files

### settings.json (optional)
Complete SAML configuration in JSON format. If this file is present, it will be used instead of environment variables.

Copy `settings.json.example` to `settings.json` and configure it with your Identity Provider (IdP) details.

### Certificates
If you're signing SAML requests or encrypting assertions, place your certificate and private key files here:
- `sp.crt` - Service Provider X.509 certificate (public key)
- `sp.key` - Service Provider private key

## Configuration Methods

### Method 1: Using settings.json file (Recommended)
1. Copy `settings.json.example` to `settings.json`
2. Update the configuration with your IdP details
3. Set environment variable: `SAML_SETTINGS_PATH=/path/to/saml_config/settings.json`

### Method 2: Using environment variables
Set the following environment variables:

```bash
# Enable SAML
export SAML_ENABLED=true

# Service Provider (SP) settings
export SAML_SP_ENTITY_ID="cellxgene-gateway"
export SAML_SP_ACS_URL="https://your-domain.com/saml/acs"
export SAML_SP_SLS_URL="https://your-domain.com/saml/sls"

# Identity Provider (IdP) settings
export SAML_IDP_ENTITY_ID="https://idp.example.com/entityid"
export SAML_IDP_SSO_URL="https://idp.example.com/sso"
export SAML_IDP_SLO_URL="https://idp.example.com/slo"
export SAML_IDP_X509_CERT="MIID..."

# Security settings (optional)
export SAML_WANT_ASSERTIONS_SIGNED=true
export SAML_WANT_MESSAGES_SIGNED=false
export SAML_SIGN_AUTHN_REQUEST=false

# Attribute mapping (optional - defaults shown)
export SAML_ATTR_USERNAME=uid
export SAML_ATTR_EMAIL=email
export SAML_ATTR_FIRST_NAME=givenName
export SAML_ATTR_LAST_NAME=sn

# Require authentication for all access
export SAML_REQUIRE_AUTHENTICATION=true

# Flask session secret (required for SAML)
export FLASK_SECRET_KEY="your-secret-key-here"
```

## Attribute Mapping

The `attributeMapping` section maps SAML attributes from your IdP to application user fields:

- `username`: The user's unique identifier
- `email`: User's email address
- `firstName`: User's first name
- `lastName`: User's last name

Update these to match the attribute names your IdP provides.

## Security Considerations

1. **Keep private keys secure**: Never commit `sp.key` or actual `settings.json` to version control
2. **Use HTTPS**: Always use HTTPS in production for SAML endpoints
3. **Validate certificates**: Ensure `wantAssertionsSigned` is set to `true` in production
4. **Rotate secrets**: Regularly update `FLASK_SECRET_KEY` and SP certificates
5. **Test thoroughly**: Test SAML integration in a staging environment before production

## Getting IdP Metadata

Most Identity Providers offer a metadata URL or file. You'll need:
- Entity ID
- Single Sign-On URL
- Single Logout URL (optional)
- X.509 Certificate

Consult your IdP documentation for specific details.

## Providing SP Metadata to IdP

Access your Service Provider metadata at: `https://your-domain.com/saml/metadata`

Provide this to your IdP administrator to complete the SAML setup.

## Testing

1. Start the gateway with SAML enabled
2. Visit `/saml/login` to initiate authentication
3. You should be redirected to your IdP login page
4. After successful authentication, you'll be redirected back to the gateway

## Troubleshooting

- Enable debug mode: `export SAML_DEBUG=true`
- Check logs for SAML-related errors
- Verify IdP certificate matches what's in configuration
- Ensure ACS URL is correctly registered with your IdP
- Check that attribute names match what your IdP sends
