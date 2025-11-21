# SAML 2.0 Implementation Checklist

Use this checklist to verify your SAML 2.0 implementation is complete and secure.

## Installation Checklist

### Dependencies
- [ ] Installed `python3-saml` library
  ```bash
  pip install python3-saml
  ```
- [ ] Verified installation:
  ```bash
  python3 -c "from onelogin.saml2.auth import OneLogin_Saml2_Auth; print('OK')"
  ```

### Configuration Files
- [ ] Reviewed `saml_config/settings.json.example`
- [ ] Created `saml_config/settings.json` (if using JSON config)
- [ ] OR set all required environment variables (if using env vars)
- [ ] Added SAML files to `.gitignore` (already done)

### Flask Configuration
- [ ] Generated `FLASK_SECRET_KEY`:
  ```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] Stored secret key securely (NOT in version control)
- [ ] Set `FLASK_SECRET_KEY` environment variable

## Identity Provider (IdP) Configuration

### Gather IdP Information
- [ ] IdP Entity ID
- [ ] IdP SSO URL
- [ ] IdP SLO URL (optional)
- [ ] IdP X.509 Certificate

### Register with IdP
- [ ] Created SAML application in IdP
- [ ] Configured ACS URL: `https://your-domain.com/saml/acs`
- [ ] Configured Entity ID: `cellxgene-gateway`
- [ ] Provided SP metadata from: `https://your-domain.com/saml/metadata`
- [ ] Configured attribute mappings in IdP
- [ ] Assigned users/groups to SAML application

### IdP Attribute Mapping
- [ ] Configured username attribute
- [ ] Configured email attribute
- [ ] Configured first name attribute (optional)
- [ ] Configured last name attribute (optional)
- [ ] Tested attribute values in IdP

## Application Configuration

### Basic Settings
- [ ] Set `SAML_ENABLED=true`
- [ ] Set `SAML_REQUIRE_AUTHENTICATION` (true or false)
- [ ] Set `EXTERNAL_PROTOCOL=https` (for production)
- [ ] Set `EXTERNAL_HOST` to your domain

### Service Provider Settings
- [ ] Set `SAML_SP_ENTITY_ID`
- [ ] Set `SAML_SP_ACS_URL`
- [ ] Set `SAML_SP_SLS_URL` (for logout)

### Identity Provider Settings
- [ ] Set `SAML_IDP_ENTITY_ID`
- [ ] Set `SAML_IDP_SSO_URL`
- [ ] Set `SAML_IDP_SLO_URL` (optional)
- [ ] Set `SAML_IDP_X509_CERT`

### Attribute Mapping
- [ ] Set `SAML_ATTR_USERNAME` (if different from default)
- [ ] Set `SAML_ATTR_EMAIL` (if different from default)
- [ ] Set `SAML_ATTR_FIRST_NAME` (if different from default)
- [ ] Set `SAML_ATTR_LAST_NAME` (if different from default)

### Security Settings
- [ ] Set `SAML_WANT_ASSERTIONS_SIGNED=true` (recommended)
- [ ] Configured `SAML_WANT_MESSAGES_SIGNED` if required by IdP
- [ ] Configured `SAML_SIGN_AUTHN_REQUEST` if required by IdP

### Proxy Configuration (if applicable)
- [ ] Set `PROXY_FIX_FOR`
- [ ] Set `PROXY_FIX_PROTO`
- [ ] Set `PROXY_FIX_HOST`
- [ ] Set `PROXY_FIX_PORT`

## Testing

### Pre-Deployment Testing
- [ ] Started gateway with `SAML_REQUIRE_AUTHENTICATION=false` (optional mode)
- [ ] Verified gateway starts without errors
- [ ] Checked logs for SAML initialization message

### SP Metadata Testing
- [ ] Accessed `/saml/metadata`
- [ ] Verified metadata XML is valid
- [ ] Confirmed metadata matches IdP configuration

### Authentication Flow Testing
- [ ] Accessed `/saml/login`
- [ ] Redirected to IdP login page
- [ ] Successfully authenticated with IdP
- [ ] Redirected back to gateway
- [ ] Session created successfully
- [ ] Can access protected resources

### Logout Flow Testing
- [ ] Accessed `/saml/logout`
- [ ] Session cleared locally
- [ ] Redirected to IdP (if SLO configured)
- [ ] Cannot access protected resources after logout

### Authorization Testing
- [ ] Verified `is_authorized()` checks work
- [ ] Tested with authenticated user
- [ ] Tested with unauthenticated user
- [ ] Tested session expiration

### Error Handling Testing
- [ ] Tested with invalid credentials
- [ ] Tested with expired assertions
- [ ] Tested with malformed responses
- [ ] Verified error messages are helpful

## Security Checklist

### HTTPS Configuration
- [ ] Using HTTPS in production (required for SAML)
- [ ] Valid SSL/TLS certificate installed
- [ ] Certificate not expired
- [ ] Redirects HTTP to HTTPS

### Session Security
- [ ] `SESSION_COOKIE_SECURE` enabled (automatic with HTTPS)
- [ ] `SESSION_COOKIE_HTTPONLY` enabled (automatic)
- [ ] `SESSION_COOKIE_SAMESITE` configured (automatic)
- [ ] Strong `FLASK_SECRET_KEY` (32+ characters)

### SAML Security
- [ ] `SAML_WANT_ASSERTIONS_SIGNED=true` in production
- [ ] IdP certificate verified and current
- [ ] No hardcoded secrets in code
- [ ] Sensitive config files not in version control

### Certificate Management
- [ ] IdP certificate stored securely
- [ ] SP certificate (if used) stored securely
- [ ] SP private key (if used) has restricted permissions (400/600)
- [ ] Certificate expiration monitoring in place

### Logging and Monitoring
- [ ] SAML authentication events logged
- [ ] Failed authentication attempts logged
- [ ] Log level appropriate for environment
- [ ] Sensitive data not logged (passwords, certificates)

## Production Deployment

### Pre-Deployment
- [ ] Tested in staging/dev environment
- [ ] Documented IdP-specific configuration
- [ ] Created runbook for SAML operations
- [ ] Prepared rollback plan

### Deployment
- [ ] Backed up existing configuration
- [ ] Deployed with `SAML_REQUIRE_AUTHENTICATION=false` first (optional)
- [ ] Verified authentication works in production
- [ ] Enabled `SAML_REQUIRE_AUTHENTICATION=true`
- [ ] Verified all users can authenticate

### Post-Deployment
- [ ] Monitored logs for errors
- [ ] Verified no authentication failures
- [ ] Tested from multiple locations/browsers
- [ ] Updated documentation with production URLs

## Documentation

### User Documentation
- [ ] Documented how users log in
- [ ] Documented how users log out
- [ ] Documented troubleshooting steps
- [ ] Provided support contact information

### Administrator Documentation
- [ ] Documented complete configuration
- [ ] Documented IdP settings
- [ ] Documented emergency procedures
- [ ] Documented certificate renewal process

### References
- [ ] Read `SAML_AUTHENTICATION.md`
- [ ] Read `SAML_QUICKSTART.md`
- [ ] Read `saml_config/README.md`
- [ ] Bookmarked IdP documentation

## Maintenance

### Regular Tasks
- [ ] Monitor SAML authentication success rate
- [ ] Review SAML-related logs weekly
- [ ] Verify certificate expiration dates monthly
- [ ] Test authentication flow quarterly

### As Needed
- [ ] Update IdP certificate when renewed
- [ ] Rotate `FLASK_SECRET_KEY` periodically
- [ ] Update `python3-saml` library
- [ ] Review and update attribute mappings

### Emergency Procedures
- [ ] Know how to disable SAML quickly:
  ```bash
  export SAML_ENABLED=false
  # or
  export SAML_REQUIRE_AUTHENTICATION=false
  ```
- [ ] Have IdP administrator contact
- [ ] Know how to check SAML logs
- [ ] Have backup authentication method (if applicable)

## Troubleshooting Reference

### Enable Debug Mode
```bash
export SAML_DEBUG=true
export GATEWAY_LOG_LEVEL=DEBUG
```

### Check Configuration
```bash
# Verify environment variables
env | grep SAML

# Check if SAML is enabled
curl -I https://your-domain.com/saml/login

# Download metadata
curl https://your-domain.com/saml/metadata
```

### Common Issues Quick Reference
1. **Can't access /saml/login**: Check `SAML_ENABLED=true`
2. **Redirect loop**: Verify `SAML_SP_ACS_URL` matches IdP config
3. **Authentication fails**: Check IdP certificate and URLs
4. **Attributes missing**: Verify IdP attribute mapping
5. **Session not persisting**: Check `FLASK_SECRET_KEY` is set

## Sign-Off

### Development Team
- [ ] Code reviewed
- [ ] Tests passed
- [ ] Documentation complete
- [ ] Security review passed

### Operations Team
- [ ] Infrastructure ready
- [ ] Monitoring configured
- [ ] Alerts configured
- [ ] Backup procedures tested

### Security Team
- [ ] Security requirements met
- [ ] Penetration testing completed (if required)
- [ ] Compliance requirements verified
- [ ] Incident response plan updated

### Stakeholders
- [ ] Business requirements met
- [ ] User acceptance testing passed
- [ ] Training completed
- [ ] Go-live approved

---

## Notes

Use this space to document any environment-specific notes or deviations from the standard configuration:

```
Environment: _________________
IdP: _________________
Deployment Date: _________________
Deployed By: _________________

Special Configurations:
- 
- 
- 

Known Issues:
- 
- 
- 

Contact Information:
- IdP Administrator: _________________
- Application Owner: _________________
- Security Contact: _________________
```

---

**Last Updated**: November 21, 2025
**Version**: 1.0
