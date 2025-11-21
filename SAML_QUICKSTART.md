# SAML 2.0 Quick Start Guide

This guide will help you quickly set up SAML 2.0 authentication for Cellxgene Gateway.

## Prerequisites

1. Access to an Identity Provider (IdP): Okta, Azure AD, Google Workspace, etc.
2. Administrative access to configure a SAML application in your IdP
3. A domain with HTTPS enabled (required for SAML in production)

## Step 1: Install Dependencies

```bash
pip install python3-saml
# or
pip install -r requirements.txt
```

## Step 2: Generate Flask Secret Key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Save this key - you'll need it for the `FLASK_SECRET_KEY` environment variable.

## Step 3: Configure Your Identity Provider

### Get Your SP Metadata

Before configuring your IdP, you need to provide Service Provider (SP) information. You can:

1. Start the gateway with minimal SAML config to get metadata, or
2. Provide these values manually:
   - **Entity ID**: `cellxgene-gateway` (or custom value)
   - **ACS URL**: `https://your-domain.com/saml/acs`
   - **Metadata URL**: `https://your-domain.com/saml/metadata`

### IdP Configuration Steps

#### For Okta:
1. In Okta Admin Console, go to **Applications > Create App Integration**
2. Select **SAML 2.0**
3. Configure:
   - **Single sign on URL**: `https://your-domain.com/saml/acs`
   - **Audience URI (SP Entity ID)**: `cellxgene-gateway`
   - **Default RelayState**: (leave empty)
4. Configure attribute statements (optional but recommended):
   - `uid` → `user.login`
   - `email` → `user.email`
   - `givenName` → `user.firstName`
   - `sn` → `user.lastName`
5. Complete setup and note:
   - **Metadata URL** or download metadata XML
   - **Identity Provider Issuer**
   - **Identity Provider Single Sign-On URL**
   - **X.509 Certificate**

#### For Azure AD:
1. Go to **Azure Active Directory > Enterprise Applications > New application**
2. Create **Non-gallery application**
3. Configure SAML:
   - **Identifier (Entity ID)**: `cellxgene-gateway`
   - **Reply URL (ACS)**: `https://your-domain.com/saml/acs`
4. Configure User Attributes:
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` → `user.userprincipalname`
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` → `user.mail`
5. Download the **Certificate (Base64)** and note:
   - **Login URL**
   - **Azure AD Identifier**

#### For Google Workspace:
1. Go to **Apps > Web and mobile apps > Add app > Add custom SAML app**
2. Download IdP metadata or note:
   - **SSO URL**
   - **Entity ID**
   - **Certificate**
3. Configure Service Provider:
   - **ACS URL**: `https://your-domain.com/saml/acs`
   - **Entity ID**: `cellxgene-gateway`
4. Configure Attribute Mapping:
   - `username` → Basic Information > Primary email
   - `email` → Basic Information > Primary email
   - `firstName` → Basic Information > First name
   - `lastName` → Basic Information > Last name

## Step 4: Configure Cellxgene Gateway

### Option A: Using Environment Variables

Create a configuration file (e.g., `saml-config.sh`):

```bash
#!/bin/bash

# Basic Gateway Configuration
export CELLXGENE_LOCATION=$(which cellxgene)
export CELLXGENE_DATA=./cellxgene_data
export GATEWAY_PORT=5005

# SAML Configuration
export SAML_ENABLED=true
export SAML_REQUIRE_AUTHENTICATION=true
export FLASK_SECRET_KEY="your-generated-secret-key-here"

# Service Provider
export SAML_SP_ENTITY_ID="cellxgene-gateway"
export SAML_SP_ACS_URL="https://your-domain.com/saml/acs"
export SAML_SP_SLS_URL="https://your-domain.com/saml/sls"

# Identity Provider (get these from your IdP)
export SAML_IDP_ENTITY_ID="https://idp.example.com/entityid"
export SAML_IDP_SSO_URL="https://idp.example.com/sso"
export SAML_IDP_X509_CERT="MIIDXTCCAkWgAwIBAgIJ..."

# External Configuration
export EXTERNAL_PROTOCOL=https
export EXTERNAL_HOST="your-domain.com"

# Optional: Attribute Mapping
export SAML_ATTR_USERNAME=uid
export SAML_ATTR_EMAIL=email

# Start Gateway
cellxgene-gateway
```

Make it executable and run:
```bash
chmod +x saml-config.sh
./saml-config.sh
```

### Option B: Using JSON Configuration File

1. Copy the example configuration:
```bash
cp saml_config/settings.json.example saml_config/settings.json
```

2. Edit `saml_config/settings.json` with your IdP details

3. Set environment variables:
```bash
export CELLXGENE_LOCATION=$(which cellxgene)
export CELLXGENE_DATA=./cellxgene_data
export SAML_ENABLED=true
export SAML_REQUIRE_AUTHENTICATION=true
export SAML_SETTINGS_PATH=./saml_config/settings.json
export FLASK_SECRET_KEY="your-generated-secret-key-here"
export EXTERNAL_PROTOCOL=https
export EXTERNAL_HOST="your-domain.com"
```

4. Start the gateway:
```bash
cellxgene-gateway
```

## Step 5: Test the Integration

1. **Access the login page**:
   ```
   https://your-domain.com/saml/login
   ```

2. **You should be redirected to your IdP** for authentication

3. **After successful login**, you'll be redirected back to the gateway

4. **Access your data** - you should now be authenticated

## Step 6: Verify SP Metadata

Your IdP administrator may need your SP metadata. It's available at:
```
https://your-domain.com/saml/metadata
```

## Troubleshooting

### Enable Debug Mode

```bash
export SAML_DEBUG=true
export GATEWAY_LOG_LEVEL=DEBUG
```

### Common Issues

**Issue**: "SAML authentication is not enabled"
- **Solution**: Ensure `SAML_ENABLED=true` is set

**Issue**: Redirect loop after IdP authentication
- **Solution**: Verify `SAML_SP_ACS_URL` exactly matches what's configured in your IdP

**Issue**: "SAML authentication failed"
- **Solution**: 
  - Check that IdP certificate is correct
  - Verify IdP URLs are correct
  - Enable debug mode to see detailed error messages

**Issue**: Attributes not mapping correctly
- **Solution**: Check what attributes your IdP sends and update `SAML_ATTR_*` variables accordingly

### Getting IdP Certificate

If you have IdP metadata XML, extract the certificate:
```bash
# From metadata URL
curl -s https://idp.example.com/metadata | grep -oP '(?<=<X509Certificate>)[^<]+'

# From metadata file
cat metadata.xml | grep -oP '(?<=<X509Certificate>)[^<]+'
```

## Security Checklist

- [ ] Using HTTPS in production (`EXTERNAL_PROTOCOL=https`)
- [ ] Generated strong `FLASK_SECRET_KEY`
- [ ] IdP certificate is correct and up to date
- [ ] `SAML_WANT_ASSERTIONS_SIGNED=true` in production
- [ ] Tested login and logout flows
- [ ] Verified user attributes are mapping correctly
- [ ] Configured proxy headers if behind reverse proxy

## Next Steps

- Read the full documentation: [SAML_AUTHENTICATION.md](SAML_AUTHENTICATION.md)
- Configure additional security settings
- Set up custom authorization logic
- Enable logging and monitoring
- Test Single Logout (SLO) functionality

## Support

For detailed information, see:
- [SAML_AUTHENTICATION.md](SAML_AUTHENTICATION.md) - Complete SAML documentation
- [saml_config/README.md](saml_config/README.md) - Configuration details
- Your IdP's SAML documentation

## Example: Complete Okta Configuration

```bash
#!/bin/bash

# Basic Configuration
export CELLXGENE_LOCATION=$(which cellxgene)
export CELLXGENE_DATA=./cellxgene_data
export GATEWAY_PORT=5005

# SAML Configuration
export SAML_ENABLED=true
export SAML_REQUIRE_AUTHENTICATION=true
export FLASK_SECRET_KEY="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"

# Service Provider
export SAML_SP_ENTITY_ID="cellxgene-gateway"
export SAML_SP_ACS_URL="https://cellxgene.example.com/saml/acs"
export SAML_SP_SLS_URL="https://cellxgene.example.com/saml/sls"

# Okta Identity Provider
export SAML_IDP_ENTITY_ID="http://www.okta.com/exkabc123xyz"
export SAML_IDP_SSO_URL="https://example.okta.com/app/exkabc123xyz/sso/saml"
export SAML_IDP_SLO_URL="https://example.okta.com/app/exkabc123xyz/slo/saml"
export SAML_IDP_X509_CERT="MIIDpDCCAoygAwIBAgIGAXv..."

# Okta Attribute Mapping
export SAML_ATTR_USERNAME=username
export SAML_ATTR_EMAIL=email
export SAML_ATTR_FIRST_NAME=firstName
export SAML_ATTR_LAST_NAME=lastName

# External Configuration
export EXTERNAL_PROTOCOL=https
export EXTERNAL_HOST="cellxgene.example.com"

# Security
export SAML_WANT_ASSERTIONS_SIGNED=true

# Start
cellxgene-gateway
```

Save this as `start-with-okta.sh`, make it executable, and run it:
```bash
chmod +x start-with-okta.sh
./start-with-okta.sh
```
