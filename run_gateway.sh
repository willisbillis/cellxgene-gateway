#!/bin/bash
pkill -f cellxgene-gateway
source .cellxgene-gateway/bin/activate

# Required: Basic Gateway Configuration
export CELLXGENE_LOCATION=$(which cellxgene)
export CELLXGENE_DATA=/home/elliott/Apps/github/cellxgene-gateway/cellxgene_data  # change this directory if you put data in a different place.
export GATEWAY_PORT=5005
export DATASET_METADATA_CSV=/home/elliott/Apps/github/cellxgene-gateway/datasets.csv
export GATEWAY_ENABLE_ANNOTATIONS=true
export GATEWAY_ENABLE_BACKED_MODE=true

# Required: SAML Configuration
export SAML_ENABLED=true
export SAML_REQUIRE_AUTHENTICATION=false  # Set to false to make SAML optional
export SAML_DEBUG=true  # Enable debug mode for troubleshooting

# Required: Flask Session Secret (GENERATE YOUR OWN!)
# Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
export FLASK_SECRET_KEY="990c4f5d290211b30cb901ffe34eaf0f819d53bdd095622fa68dab23214f56ef"

# Required: Service Provider URLs (update with your actual domain)
export SAML_SP_ENTITY_ID="cellxgene-gateway"
export SAML_SP_ACS_URL="https://cellxgene-gateway.emory.edu/saml/acs"
export SAML_SP_SLS_URL="https://cellxgene-gateway.emory.edu/saml/sls"

# Required: Identity Provider Configuration
# Get these values from your IdP (Okta, Azure AD, Google Workspace, etc.)
export SAML_IDP_ENTITY_ID="https://login.emory.edu/entityid"
export SAML_IDP_SSO_URL="https://login.emory.edu/sso"
export SAML_IDP_SLO_URL="https://login.emory.edu/slo"  # Optional
export SAML_IDP_X509_CERT=""

cellxgene-gateway &