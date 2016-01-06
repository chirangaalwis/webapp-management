/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wso2.appserver.webapp.mgt.identity.sso.agent;

/**
 * This class defines the constants utilized in the single-sign-on (SSO) Agent implementation.
 *
 * @since 6.0.0
 */
public class SSOAgentConstants {
    public static final String SESSION_BEAN_NAME = "org.wso2.carbon.identity.sso.agent.LoggedInSessionBean";

    /**
     * Prevents instantiating the SSOAgentConstants class
     */
    private SSOAgentConstants() {
    }

    /**
     * This class defines the constants associated during the SAML 2.0 based single-sign-on (SSO) communication.
     */
    public static class SAML2SSO {
        /**
         * Prevents instantiating the SAML2SSO nested class
         */
        private SAML2SSO() {
        }

        //  SAML 2.0 single-sign-on (SSO) parameter name constants
        public static final String HTTP_POST_PARAM_SAML2_REQUEST = "SAMLRequest";
        public static final String HTTP_POST_PARAM_SAML2_RESPONSE = "SAMLResponse";

        public static final String LOGOUT_REQUEST_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        public static final String LOGOUT_REQUEST_REASON = "Single Logout";

        public static final String AUTH_REQUEST_NAME_ID_POLICY_FORMAT =
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        public static final String AUTH_REQUEST_SERVICE_PROVIDER_NAME_QUALIFIER = "Issuer";
        public static final String AUTH_CONTEXT_CLASS_URI_REFERENCE =
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    }

    /**
     * This class defines the single-sign-on (SSO) Agent configuration property name constants.
     */
    public static class SSOAgentConfiguration {
        public static final String ENABLE_SAML2_SSO_LOGIN = "EnableSAML2SSOLogin";
        public static final String ENABLE_OAUTH2_SAML2_OAUTH2_GRANT = "EnableOAuth2SAML2Grant";
        public static final String SAML2_SSO_URL = "SAML2SSOURL";
        public static final String OAUTH2_SAML2_GRANT_URL = "OAuth2SAML2GrantURL";
        public static final String SKIP_URIS = "SkipURIs";
        public static final String QUERY_PARAMS = "QueryParams";

        /**
         * Prevents instantiating the SSOAgentConfiguration nested class
         */
        private SSOAgentConfiguration() {
        }

        /**
         * This class defines the SAML 2.0 specific single-sign-on (SSO) configuration property name constants.
         */
        public static class SAML2 {
            public static final String HTTP_BINDING = "SAML2.HTTPBinding";
            public static final String SP_ENTITY_ID = "SAML2.SPEntityId";
            public static final String ACS_URL = "SAML2.AssertionConsumerURL";
            public static final String IDP_ENTITY_ID = "SAML2.IdPEntityId";
            public static final String IDP_URL = "SAML2.IdPURL";
            public static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "SAML2.AttributeConsumingServiceIndex";
            public static final String ENABLE_SLO = "SAML2.EnableSLO";
            public static final String SLO_URL = "SAML2.SLOURL";
            public static final String ENABLE_ASSERTION_SIGNING = "SAML2.EnableAssertionSigning";
            public static final String ENABLE_ASSERTION_ENCRYPTION = "SAML2.EnableAssertionEncryption";
            public static final String ENABLE_RESPONSE_SIGNING = "SAML2.EnableResponseSigning";
            public static final String ENABLE_REQUEST_SIGNING = "SAML2.EnableRequestSigning";
            public static final String IS_PASSIVE_AUTHN = "SAML2.IsPassiveAuthn";
            public static final String IS_FORCE_AUTHN = "SAML2.IsForceAuthn";
            public static final String RELAY_STATE = "SAML2.RelayState";
            public static final String POST_BINDING_REQUEST_HTML_PAYLOAD = "SAML2.PostBindingRequestHTMLPayload";
            public static final String SIGNATURE_VALIDATOR = "SAML2.SignatureValidatorImplClass";

            /**
             * Prevents instantiating the SAML2 nested class
             */
            private SAML2() {
            }
        }

        /**
         * This class defines the OAuth 2.0 specific single-sign-on (SSO) configuration property name constants.
         */
        public static class OAuth2 {
            public static final String CLIENT_ID = "OAuth2.ClientId";
            public static final String CLIENT_SECRET = "OAuth2.ClientSecret";
            public static final String TOKEN_URL = "OAuth2.TokenURL";

            /**
             * Prevents instantiating the OAuth2 nested class
             */
            private OAuth2() {
            }
        }

    }
}
