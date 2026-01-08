# Copyright 2019 Novartis Institutes for BioMedical Research Inc. Licensed
# under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless
# required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

"""
SAML 2.0 Authentication Module for Cellxgene Gateway
Provides SAML-based single sign-on (SSO) authentication.
"""

import json
import logging
import os
from typing import Dict, Optional

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

logger = logging.getLogger(__name__)


class SAMLConfig:
    """SAML configuration manager"""

    def __init__(self, settings_path: Optional[str] = None):
        """
        Initialize SAML configuration.
        
        Args:
            settings_path: Path to SAML settings JSON file. If None, uses environment variables.
        """
        self.settings_path = settings_path
        self._settings_dict = None

    def load_settings(self) -> Dict:
        """Load SAML settings from file or environment variables."""
        if self._settings_dict is not None:
            return self._settings_dict

        if self.settings_path and os.path.exists(self.settings_path):
            # Load from JSON file
            with open(self.settings_path, 'r') as f:
                self._settings_dict = json.load(f)
                logger.info(f"Loaded SAML settings from {self.settings_path}")
        else:
            # Build from environment variables
            self._settings_dict = self._build_settings_from_env()
            logger.info("Built SAML settings from environment variables")

        return self._settings_dict

    def _build_settings_from_env(self) -> Dict:
        """Build SAML settings dictionary from environment variables."""
        # Get environment variables with defaults
        sp_entity_id = os.environ.get("SAML_SP_ENTITY_ID", "cellxgene-gateway")
        sp_acs_url = os.environ.get("SAML_SP_ACS_URL", "http://localhost:5005/saml/acs")
        sp_sls_url = os.environ.get("SAML_SP_SLS_URL", "http://localhost:5005/saml/sls")
        
        idp_entity_id = os.environ.get("SAML_IDP_ENTITY_ID", "")
        idp_sso_url = os.environ.get("SAML_IDP_SSO_URL", "")
        idp_slo_url = os.environ.get("SAML_IDP_SLO_URL", "")
        idp_x509_cert = os.environ.get("SAML_IDP_X509_CERT", "")
        
        # Optional SP certificate and key for request signing
        sp_x509_cert = os.environ.get("SAML_SP_X509_CERT", "")
        sp_private_key = os.environ.get("SAML_SP_PRIVATE_KEY", "")
        
        # Security settings
        want_assertions_signed = os.environ.get("SAML_WANT_ASSERTIONS_SIGNED", "true").lower() == "true"
        want_messages_signed = os.environ.get("SAML_WANT_MESSAGES_SIGNED", "false").lower() == "true"
        want_assertions_encrypted = os.environ.get("SAML_WANT_ASSERTIONS_ENCRYPTED", "false").lower() == "true"
        sign_authn_request = os.environ.get("SAML_SIGN_AUTHN_REQUEST", "false").lower() == "true"
        sign_logout_request = os.environ.get("SAML_SIGN_LOGOUT_REQUEST", "false").lower() == "true"
        sign_logout_response = os.environ.get("SAML_SIGN_LOGOUT_RESPONSE", "false").lower() == "true"
        
        # If no IdP cert, disable signature requirements for metadata generation
        if not idp_x509_cert:
            want_assertions_signed = False
            want_messages_signed = False
        
        # Attribute mapping
        attr_username = os.environ.get("SAML_ATTR_USERNAME", "uid")
        attr_email = os.environ.get("SAML_ATTR_EMAIL", "email")
        attr_first_name = os.environ.get("SAML_ATTR_FIRST_NAME", "givenName")
        attr_last_name = os.environ.get("SAML_ATTR_LAST_NAME", "sn")
        
        # Use non-strict mode if IdP certificate is not provided (for metadata generation)
        strict_mode = True
        if not idp_x509_cert:
            strict_mode = False
            logger.info("SAML strict mode disabled - IdP certificate not configured")
        
        settings = {
            "strict": strict_mode,
            "debug": os.environ.get("SAML_DEBUG", "false").lower() == "true",
            "sp": {
                "entityId": sp_entity_id,
                "assertionConsumerService": {
                    "url": sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": sp_sls_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": sp_x509_cert,
                "privateKey": sp_private_key
            },
            "idp": {
                "entityId": idp_entity_id,
                "singleSignOnService": {
                    "url": idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "singleLogoutService": {
                    "url": idp_slo_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": idp_x509_cert
            },
            "security": {
                "nameIdEncrypted": False,
                "authnRequestsSigned": sign_authn_request,
                "logoutRequestSigned": sign_logout_request,
                "logoutResponseSigned": sign_logout_response,
                "signMetadata": False,
                "wantMessagesSigned": want_messages_signed,
                "wantAssertionsSigned": want_assertions_signed,
                "wantAssertionsEncrypted": want_assertions_encrypted,
                "wantNameId": True,
                "wantNameIdEncrypted": False,
                "wantAttributeStatement": True,
                "requestedAuthnContext": True,
                "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
            },
            "attributeMapping": {
                "username": attr_username,
                "email": attr_email,
                "firstName": attr_first_name,
                "lastName": attr_last_name
            }
        }
        
        return settings

    def prepare_flask_request(self, request):
        """
        Prepare request data in the format expected by python3-saml.
        
        Args:
            request: Flask request object
            
        Returns:
            Dictionary with request data formatted for python3-saml
        """
        url_data = {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'server_port': request.environ.get('SERVER_PORT', '80'),
            'script_name': request.path,
            'get_data': request.args.copy(),
            'post_data': request.form.copy()
        }
        
        # Handle reverse proxy headers
        if 'HTTP_X_FORWARDED_FOR' in request.environ:
            url_data['http_x_forwarded_for'] = request.environ['HTTP_X_FORWARDED_FOR']
        if 'HTTP_X_FORWARDED_PROTO' in request.environ:
            url_data['https'] = 'on' if request.environ['HTTP_X_FORWARDED_PROTO'] == 'https' else 'off'
        if 'HTTP_X_FORWARDED_HOST' in request.environ:
            url_data['http_host'] = request.environ['HTTP_X_FORWARDED_HOST']
        if 'HTTP_X_FORWARDED_PORT' in request.environ:
            url_data['server_port'] = request.environ['HTTP_X_FORWARDED_PORT']
            
        return url_data

    def init_saml_auth(self, request):
        """
        Initialize SAML authentication object.
        
        Args:
            request: Flask request object
            
        Returns:
            OneLogin_Saml2_Auth instance
        """
        settings = self.load_settings()
        req = self.prepare_flask_request(request)
        auth = OneLogin_Saml2_Auth(req, settings)
        return auth


def extract_user_attributes(auth: OneLogin_Saml2_Auth, settings: Dict) -> Dict:
    """
    Extract user attributes from SAML response.
    
    Args:
        auth: Authenticated SAML auth object
        settings: SAML settings dictionary with attribute mapping
        
    Returns:
        Dictionary with user information
    """
    attributes = auth.get_attributes()
    attribute_mapping = settings.get("attributeMapping", {})
    
    def get_attr(attr_name: str, default: str = "") -> str:
        """Get attribute value from SAML response."""
        saml_attr = attribute_mapping.get(attr_name, attr_name)
        values = attributes.get(saml_attr, [])
        return values[0] if values else default
    
    user_info = {
        "nameid": auth.get_nameid(),
        "username": get_attr("username"),
        "email": get_attr("email"),
        "first_name": get_attr("firstName"),
        "last_name": get_attr("lastName"),
        "session_index": auth.get_session_index(),
        "attributes": attributes  # Store all attributes for reference
    }
    
    # Use nameid as username if no username attribute
    if not user_info["username"]:
        user_info["username"] = user_info["nameid"]
    
    return user_info


def is_saml_enabled() -> bool:
    """Check if SAML authentication is enabled."""
    settings_path = os.environ.get("SAML_SETTINGS_PATH")
    idp_entity_id = os.environ.get("SAML_IDP_ENTITY_ID")
    
    # SAML is enabled if either settings file exists or IdP is configured
    if settings_path and os.path.exists(settings_path):
        return True
    if idp_entity_id:
        return True
    
    return False


def get_saml_config() -> Optional[SAMLConfig]:
    """Get SAML configuration if enabled."""
    if not is_saml_enabled():
        return None
    
    settings_path = os.environ.get("SAML_SETTINGS_PATH")
    return SAMLConfig(settings_path)
