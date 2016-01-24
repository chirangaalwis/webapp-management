/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.appserver.webapp.security.sso;

/**
 * This class defines the constants utilized used within the org.wso2.appserver.webapp.security.sso.
 *
 * @since 6.0.0
 */
public class SSOConstants {
    public static final String SESSION_BEAN_NAME = "org.wso2.appserver.webapp.security.sso.bean.LoggedInSession";

    /**
     * Prevents instantiating the SSOConstants class.
     */
    private SSOConstants() {
    }

    /**
     * This class defines the constants associated during the SAML 2.0 based single-sign-on (SSO) communication.
     */
    public static class SAML2SSO {
        //  SAML 2.0 single-sign-on (SSO) parameter name constants
        public static final String HTTP_POST_PARAM_SAML2_REQUEST = "SAMLRequest";
        public static final String HTTP_POST_PARAM_SAML2_RESPONSE = "SAMLResponse";

        /**
         * Prevents instantiating the SAML2SSO nested class.
         */
        private SAML2SSO() {
        }
    }

    /**
     * This class defines the single-sign-on (SSO) agent configuration property name constants.
     */
    public static class SSOAgentConfiguration {
        public static final String SKIP_URIS = "SkipURIs";
        public static final String QUERY_PARAMS = "QueryParams";

        /**
         * Prevents instantiating the SSOAgentConfiguration nested class.
         */
        private SSOAgentConfiguration() {
        }

        /**
         * This class defines the SAML 2.0 specific single-sign-on (SSO) configuration property name constants.
         */
        public static class SAML2 {
            public static final String ENABLE_SAML2_SSO_LOGIN = "EnableSAML2SSOLogin";
            public static final String SAML2_SSO_URL = "SAML2SSOURL";

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
            public static final String CONSUMER_URL_POSTFIX = "SAML.ConsumerUrlPostFix";

            //  Digital signature configuration properties
            public static final String KEYSTORE_PATH = "SAML.KeyStorePath";
            public static final String KEYSTORE_PASSWORD = "SAML.KeyStorePassword";
            public static final String IDP_PUBLIC_CERTIFICATE_ALIAS = "SAML.IdPCertAlias";
            public static final String SP_PRIVATE_KEY_ALIAS = "SAML.PrivateKeyAlias";
            public static final String SP_PRIVATE_KEY_PASSWORD = "SAML.PrivateKeyPassword";
            public static final String SIGNATURE_VALIDATOR = "SAML2.SignatureValidatorImplClass";

            /**
             * Prevents instantiating the SAML2 nested class.
             */
            private SAML2() {
            }
        }
    }

    /**
     * This class defines constants used in the implementation of the SAML 2.0 single-sign-on (SSO) valve.
     */
    public static class SAMLSSOValveConstants {
        //  Environmental variable property name constant
        protected static final String CATALINA_BASE = "catalina.base";
        //  SSO configuration XML element tag name
        protected static final String SINGLE_SIGN_ON_CONFIG_TAG_NAME = "wwc:single-sign-on";
        //  File path related constants
        protected static final String TOMCAT_CONFIGURATION_FOLDER_NAME = "conf";
        protected static final String WSO2_CONFIGURATION_FOLDER_NAME = "wso2";
        protected static final String WSO2AS_CONFIG_FILE_NAME = "wso2as-web.xml";
        public static final String SSO_CONFIG_FILE_NAME = "sso-sp-config.properties";
        //  HTTP servlet request session notes' property name and attribute name constants
        public static final String SSO_AGENT_CONFIG = "SSOAgentConfig";
        public static final String REQUEST_PARAM_MAP = "REQUEST_PARAM_MAP";
        //  SSO configuration property name constants
        public static final String APP_SERVER_URL = "ApplicationServerURL";
        public static final String HANDLE_CONSUMER_URL_AFTER_SLO = "handleConsumerURLAfterSLO";

        public static final String REDIRECT_PATH_AFTER_SLO = "redirectPathAfterSLO";

        /**
         * Prevents instantiating the SAMLSSOValveConstants nested class.
         */
        private SAMLSSOValveConstants() {
        }
    }
}
