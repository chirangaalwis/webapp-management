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
package org.wso2.appserver.webapp.mgt.identity.sso.agent.model;

import org.opensaml.common.xml.SAMLConstants;
import org.wso2.appserver.webapp.mgt.identity.sso.SSOException;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.SSOAgentConstants;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.util.SSOAgentUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * This class defines the configuration aspects of the single-sign-on (SSO) agent.
 *
 * @since 6.0.0
 */
public class SSOAgentConfiguration {

    // TODO: possible use of catalina X509 certificate reader
    // TODO: added new features in the new carbon-identity version master branch

    private static final Logger logger = Logger.getLogger(SSOAgentConfiguration.class.getName());

    private Boolean isSAML2SSOLoginEnabled;
    private Boolean isOAuth2SAML2GrantEnabled;

    private String saml2SSOURL;
    private String oauth2SAML2GrantURL;
    private Set<String> skipURIs;

    private Map<String, String[]> queryParameters;

    private SAML2 saml2;
    private OAuth2 oauth2;

    //  An instance field initialization block
    {
        setQueryParameters(new HashMap<>());
        setSkipURIs(new HashSet<>());
        setSAML2(new SAML2());
        setOAuth2(new OAuth2());
    }

    private static Logger getLogger() {
        return logger;
    }

    public Boolean isSAML2SSOLoginEnabled() {
        return isSAML2SSOLoginEnabled;
    }

    public void setSAML2SSOLoginEnabled(Boolean isSAML2SSOLoginEnabled) {
        this.isSAML2SSOLoginEnabled = isSAML2SSOLoginEnabled;
    }

    public Boolean isOAuth2SAML2GrantEnabled() {
        return isOAuth2SAML2GrantEnabled;
    }

    public void setOAuth2SAML2GrantEnabled(Boolean isOAuth2SAML2GrantEnabled) {
        this.isOAuth2SAML2GrantEnabled = isOAuth2SAML2GrantEnabled;
    }

    public String getSAML2SSOURL() {
        return saml2SSOURL;
    }

    public void setSAML2SSOURL(String saml2SSOURL) {
        this.saml2SSOURL = saml2SSOURL;
    }

    public String getOAuth2SAML2GrantURL() {
        return oauth2SAML2GrantURL;
    }

    public void setOAuth2SAML2GrantURL(String oauth2SAML2GrantURL) {
        this.oauth2SAML2GrantURL = oauth2SAML2GrantURL;
    }

    public Set<String> getSkipURIs() {
        return skipURIs;
    }

    public void setSkipURIs(Set<String> skipURIs) {
        this.skipURIs = skipURIs;
    }

    public Map<String, String[]> getQueryParameters() {
        return queryParameters;
    }

    public void setQueryParameters(Map<String, String[]> queryParameters) {
        this.queryParameters = queryParameters;
    }

    public SAML2 getSAML2() {
        return saml2;
    }

    private void setSAML2(SAML2 saml2) {
        this.saml2 = saml2;
    }

    public OAuth2 getOAuth2() {
        return oauth2;
    }

    private void setOAuth2(OAuth2 oauth2) {
        this.oauth2 = oauth2;
    }

    /**
     * Sets up the single-sign-on (SSO) agent configurations based on the {@code properties} defined.
     *
     * @param properties the set of properties to be used to set up the SSO Agent configuration properties
     */
    public void initConfig(Properties properties) {
        Optional.ofNullable(properties).ifPresent(configProperties -> {
            Optional<String> isSAML2SSOLoginEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.ENABLE_SAML2_SSO_LOGIN));
            if (isSAML2SSOLoginEnabledString.isPresent()) {
                setSAML2SSOLoginEnabled(Boolean.parseBoolean(isSAML2SSOLoginEnabledString.get()));
            } else {
                getLogger().log(Level.FINE, SSOAgentConstants.SSOAgentConfiguration.ENABLE_SAML2_SSO_LOGIN +
                        " not configured. Defaulting to \'false\'.");
                setSAML2SSOLoginEnabled(false);
            }

            Optional<String> isSAML2OAuth2GrantEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.ENABLE_OAUTH2_SAML2_OAUTH2_GRANT));
            if (isSAML2OAuth2GrantEnabledString.isPresent()) {
                setOAuth2SAML2GrantEnabled(Boolean.parseBoolean(isSAML2OAuth2GrantEnabledString.get()));
            } else {
                getLogger().log(Level.FINE, SSOAgentConstants.SSOAgentConfiguration.ENABLE_OAUTH2_SAML2_OAUTH2_GRANT +
                        " not configured. Defaulting to \'false\'.");
                setOAuth2SAML2GrantEnabled(false);
            }

            setSAML2SSOURL(configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2_SSO_URL));
            setOAuth2SAML2GrantURL(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.OAUTH2_SAML2_GRANT_URL));

            String skipURIsString = configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.SKIP_URIS);
            if (!SSOAgentUtils.isBlank(skipURIsString)) {
                String[] skipURIArray = skipURIsString.split(",");
                Stream.of(skipURIArray).forEach(getSkipURIs()::add);
            }

            String queryParameterString = configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.QUERY_PARAMS);
            if (!SSOAgentUtils.isBlank(queryParameterString)) {
                Map<String, List<String>> queryParameterMap = new HashMap<>();

                Stream.of(queryParameterString.split("&")).
                        map(queryParameter -> queryParameter.split("=")).forEach(splitParameters -> {
                    if (splitParameters.length == 2) {
                        if (Optional.ofNullable(queryParameterMap.get(splitParameters[0])).isPresent()) {
                            queryParameterMap.get(splitParameters[0]).add(splitParameters[1]);
                        } else {
                            List<String> newList = new ArrayList<>();
                            newList.add(splitParameters[1]);
                            queryParameterMap.put(splitParameters[0], newList);
                        }
                    }
                    queryParameterMap.entrySet().stream().forEach(entry -> {
                        String[] values = entry.getValue().toArray(new String[entry.getValue().size()]);
                        getQueryParameters().put(entry.getKey(), values);
                    });
                });
            }

            getSAML2().setHttpBinding(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.HTTP_BINDING));
            if ((!Optional.ofNullable(getSAML2().getHttpBinding()).isPresent()) || getSAML2().getHttpBinding().
                    isEmpty()) {
                getLogger().log(Level.FINE, SSOAgentConstants.SSOAgentConfiguration.SAML2.HTTP_BINDING +
                        " not configured. Defaulting to \'" + SAMLConstants.SAML2_POST_BINDING_URI + "\'.");
                getSAML2().setHttpBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            }
            getSAML2().setSPEntityId(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.SP_ENTITY_ID));
            getSAML2().setACSURL(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.ACS_URL));
            getSAML2().setIdPEntityId(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.IDP_ENTITY_ID));
            getSAML2().
                    setIdPURL(configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.IDP_URL));
            getSAML2().setAttributeConsumingServiceIndex(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.ATTRIBUTE_CONSUMING_SERVICE_INDEX));

            Optional<String> isSLOEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_SLO));
            if (isSLOEnabledString.isPresent()) {
                getSAML2().setSLOEnabled(Boolean.parseBoolean(isSLOEnabledString.get()));
            } else {
                getLogger().log(Level.INFO, "\'" + SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_SLO +
                        "\' not configured. Defaulting to \'false\'.");
                getSAML2().setSLOEnabled(false);
            }
            getSAML2().
                    setSLOURL(configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.SLO_URL));

            Optional<String> isAssertionSignedString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_SIGNING));
            if (isAssertionSignedString.isPresent()) {
                getSAML2().setAssertionSigned(Boolean.parseBoolean(isAssertionSignedString.get()));
            } else {
                getLogger().log(Level.FINE, SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_SIGNING +
                        " not configured. Defaulting to \'false\'.");
                getSAML2().setAssertionSigned(false);
            }

            Optional<String> isAssertionEncryptedString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_ENCRYPTION));
            if (isAssertionEncryptedString.isPresent()) {
                getSAML2().setAssertionEncrypted(Boolean.parseBoolean(isAssertionEncryptedString.get()));
            } else {
                getLogger().log(Level.FINE, SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_ENCRYPTION +
                        " not configured. Defaulting to \'false\'.");
                getSAML2().setAssertionEncrypted(false);
            }

            Optional<String> isResponseSignedString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_RESPONSE_SIGNING));
            if (isResponseSignedString.isPresent()) {
                getSAML2().setResponseSigned(Boolean.parseBoolean(isResponseSignedString.get()));
            } else {
                getLogger().log(Level.FINE, SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_RESPONSE_SIGNING +
                        " not configured. Defaulting to \'false\'.");
                getSAML2().setResponseSigned(false);
            }

            if (getSAML2().isResponseSigned()) {
                Optional<String> signatureValidatorImplClass = Optional.ofNullable(configProperties.
                        getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.SIGNATURE_VALIDATOR));
                if (signatureValidatorImplClass.isPresent()) {
                    getSAML2().setSignatureValidatorImplClass(signatureValidatorImplClass.get());
                } else {
                    getLogger().log(Level.FINE,
                            SSOAgentConstants.SSOAgentConfiguration.SAML2.SIGNATURE_VALIDATOR + " not configured.");
                }
            }

            Optional<String> isRequestSignedString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_REQUEST_SIGNING));
            if (isRequestSignedString.isPresent()) {
                getSAML2().setRequestSigned(Boolean.parseBoolean(isRequestSignedString.get()));
            } else {
                getLogger().log(Level.FINE, SSOAgentConstants.SSOAgentConfiguration.SAML2.ENABLE_REQUEST_SIGNING +
                        " not configured. Defaulting to \'false\'.");
                getSAML2().setRequestSigned(false);
            }

            Optional<String> isPassiveAuthenticationEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.IS_PASSIVE_AUTHN));
            if (isPassiveAuthenticationEnabledString.isPresent()) {
                getSAML2().setPassiveAuthn(Boolean.parseBoolean(isPassiveAuthenticationEnabledString.get()));
            } else {
                getLogger().log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfiguration.SAML2.IS_PASSIVE_AUTHN +
                        "\' not configured. Defaulting to \'false\'.");
                getSAML2().setPassiveAuthn(false);
            }

            Optional<String> isForceAuthenticationEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.IS_FORCE_AUTHN));
            if (isForceAuthenticationEnabledString.isPresent()) {
                getSAML2().setForceAuthn(Boolean.parseBoolean(isForceAuthenticationEnabledString.get()));
            } else {
                getLogger().log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfiguration.SAML2.IS_FORCE_AUTHN +
                        "\' not configured. Defaulting to \'false\'.");
                getSAML2().setForceAuthn(false);
            }

            getSAML2().setRelayState(
                    configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.RELAY_STATE));
            getSAML2().setPostBindingRequestHTMLPayload(configProperties.
                    getProperty(SSOAgentConstants.SSOAgentConfiguration.SAML2.POST_BINDING_REQUEST_HTML_PAYLOAD));

            getOAuth2().setTokenURL(
                    configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.OAuth2.TOKEN_URL));
            getOAuth2().setClientId(
                    configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.OAuth2.CLIENT_ID));
            getOAuth2().setClientSecret(
                    configProperties.getProperty(SSOAgentConstants.SSOAgentConfiguration.OAuth2.CLIENT_SECRET));
        });
    }

    /**
     * Verifies the validity of single-sign-on (SSO) agent configurations at the current state of this
     * SSOAgentConfiguration instance.
     *
     * @throws SSOException if the relevant configurations are invalidly set at the current state of the
     *                           SSOAgentConfiguration instance
     */
    public void verifyConfig() throws SSOException {
        if (isSAML2SSOLoginEnabled() && (!Optional.ofNullable(getSAML2SSOURL()).isPresent())) {
            throw new SSOException("\'" +
                    SSOAgentConstants.SSOAgentConfiguration.SAML2_SSO_URL + "\' not configured.");
        }

        if (!isSAML2SSOLoginEnabled() && isOAuth2SAML2GrantEnabled()) {
            throw new SSOException("SAML2 SSO Login is disabled. Cannot use SAML2 Bearer Grant type for OAuth2.");
        }

        if (isSAML2SSOLoginEnabled() && isOAuth2SAML2GrantEnabled() && (!Optional.ofNullable(getOAuth2SAML2GrantURL()).
                isPresent())) {
            throw new SSOException("\'" +
                    SSOAgentConstants.SSOAgentConfiguration.OAUTH2_SAML2_GRANT_URL + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled() && (!Optional.ofNullable(getSAML2().getSPEntityId()).isPresent())) {
            throw new SSOException("\'" +
                    SSOAgentConstants.SSOAgentConfiguration.SAML2.SP_ENTITY_ID + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled() && (!Optional.ofNullable(getSAML2().getACSURL()).isPresent())) {
            throw new SSOException("\'" +
                    SSOAgentConstants.SSOAgentConfiguration.SAML2.ACS_URL + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled() && (!Optional.ofNullable(getSAML2().getIdPEntityId()).isPresent())) {
            throw new SSOException("\'" +
                    SSOAgentConstants.SSOAgentConfiguration.SAML2.IDP_ENTITY_ID + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled() && (!Optional.ofNullable(getSAML2().getIdPURL()).isPresent())) {
            throw new SSOException("\'" +
                    SSOAgentConstants.SSOAgentConfiguration.SAML2.IDP_URL + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled() && (!Optional.ofNullable(getSAML2().getAttributeConsumingServiceIndex()).
                isPresent())) {
            getLogger().log(Level.FINE,
                    "\'" + SSOAgentConstants.SSOAgentConfiguration.SAML2.ATTRIBUTE_CONSUMING_SERVICE_INDEX +
                            "\' not configured. No attributes of the Subject will be requested.");
        }

        if (isSAML2SSOLoginEnabled() && getSAML2().isSLOEnabled() && (!Optional.ofNullable(getSAML2().
                getSLOURL()).isPresent())) {
            throw new SSOException("Single Logout enabled, but SLO URL not configured.");
        }

        // TODO: SSOAgentX509Credential has to be considered

        /*if (isSAML2SSOLoginEnabled() &&
                (saml2Instance.isAssertionSigned() ||
                saml2Instance.isAssertionEncrypted() || saml2Instance.isResponseSigned() ||
                        saml2Instance.isRequestSigned()) && saml2.ssoAgentX509Credential == null) {
            getLogger().log(Level.FINE,
                    "\'SSOAgentX509Credential\' not configured. Defaulting to " + SSOAgentCarbonX509Credential.class
                            .getName());
        }

        if (isSAML2SSOLoginEnabled() &&
                (saml2Instance.isAssertionSigned() || saml2Instance.isResponseSigned()) &&
                saml2.ssoAgentX509Credential.getEntityCertificate() == null) {
            throw new SSOAgentException("Public certificate of IdP not configured");
        }

        if (isSAML2SSOLoginEnabled() &&
                (saml2Instance.isRequestSigned() || saml2Instance.isAssertionEncrypted()) &&
                saml2.ssoAgentX509Credential.getPrivateKey() == null) {
            throw new SSOAgentException("Private key of SP not configured");
        }*/

        if (isSAML2SSOLoginEnabled() && isOAuth2SAML2GrantEnabled() &&
                (!Optional.ofNullable(getOAuth2().getTokenURL()).isPresent())) {
            throw new SSOException("OAuth2 Token endpoint not configured");
        }

        if (isSAML2SSOLoginEnabled() && isOAuth2SAML2GrantEnabled() &&
                (!Optional.ofNullable(getOAuth2().getClientId()).isPresent())) {
            throw new SSOException("OAuth2 Client Id not configured");
        }

        if (isSAML2SSOLoginEnabled() && isOAuth2SAML2GrantEnabled() &&
                (!Optional.ofNullable(getOAuth2().getClientSecret()).isPresent())) {
            throw new SSOException("OAuth2 Client Secret not configured");
        }
    }

    /**
     * A nested class which defines the SAML 2.0 SSO configuration properties.
     */
    public static class SAML2 {
        private String httpBinding;
        private String spEntityId;
        private String acsURL;
        private String idPEntityId;
        private String idPURL;
        private Boolean isSLOEnabled;
        private String sloURL;
        private String attributeConsumingServiceIndex;
//        private SSOAgentX509Credential ssoAgentX509Credential = null;
        private Boolean isAssertionSigned;
        private Boolean isAssertionEncrypted;
        private Boolean isResponseSigned;
        private Boolean isRequestSigned;
        private Boolean isPassiveAuthenticationEnabled;
        private Boolean isForceAuthenticationEnabled;
        private String relayState;
        private String signatureValidatorImplClass;
        /**
         * The html page that will auto-submit the SAML2 to the IdP.
         * This should be in valid HTML syntax, with following section within the
         * auto-submit form.
         * "&lt;!--$saml_params--&gt;"
         * This section will be replaced by the SAML2 parameters.
         * <p>
         * If the parameter value is empty, null or doesn't have the above
         * section, the default page will be shown
         */
        private String postBindingRequestHTMLPayload;

        public String getHttpBinding() {
            return httpBinding;
        }

        public void setHttpBinding(String httpBinding) {
            this.httpBinding = httpBinding;
        }

        public String getSPEntityId() {
            return spEntityId;
        }

        public void setSPEntityId(String spEntityId) {
            this.spEntityId = spEntityId;
        }

        public String getACSURL() {
            return acsURL;
        }

        public void setACSURL(String acsURL) {
            this.acsURL = acsURL;
        }

        public String getIdPEntityId() {
            return idPEntityId;
        }

        public void setIdPEntityId(String idPEntityId) {
            this.idPEntityId = idPEntityId;
        }

        public String getIdPURL() {
            return idPURL;
        }

        public void setIdPURL(String idPURL) {
            this.idPURL = idPURL;
        }

        public Boolean isSLOEnabled() {
            return isSLOEnabled;
        }

        public void setSLOEnabled(Boolean isSLOEnabled) {
            this.isSLOEnabled = isSLOEnabled;
        }

        public String getSLOURL() {
            return sloURL;
        }

        public void setSLOURL(String sloURL) {
            this.sloURL = sloURL;
        }

        public String getAttributeConsumingServiceIndex() {
            return attributeConsumingServiceIndex;
        }

        public void setAttributeConsumingServiceIndex(String attributeConsumingServiceIndex) {
            this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
        }

        // TODO: SSOAgentX509Credential has to be considered

        /*public SSOAgentX509Credential getSSOAgentX509Credential() {
            return ssoAgentX509Credential;
        }

        public void setSSOAgentX509Credential(SSOAgentX509Credential ssoAgentX509Credential) {
            this.ssoAgentX509Credential = ssoAgentX509Credential;
        }*/

        public Boolean isAssertionSigned() {
            return isAssertionSigned;
        }

        public void setAssertionSigned(Boolean isAssertionSigned) {
            this.isAssertionSigned = isAssertionSigned;
        }

        public Boolean isAssertionEncrypted() {
            return isAssertionEncrypted;
        }

        public void setAssertionEncrypted(Boolean isAssertionEncrypted) {
            this.isAssertionEncrypted = isAssertionEncrypted;
        }

        public Boolean isResponseSigned() {
            return isResponseSigned;
        }

        public void setResponseSigned(Boolean isResponseSigned) {
            this.isResponseSigned = isResponseSigned;
        }

        public Boolean isRequestSigned() {
            return isRequestSigned;
        }

        public void setRequestSigned(Boolean isRequestSigned) {
            this.isRequestSigned = isRequestSigned;
        }

        public Boolean isPassiveAuthn() {
            return isPassiveAuthenticationEnabled;
        }

        public void setPassiveAuthn(Boolean isPassiveAuthn) {
            this.isPassiveAuthenticationEnabled = isPassiveAuthn;
        }

        public Boolean isForceAuthn() {
            return isForceAuthenticationEnabled;
        }

        public void setForceAuthn(Boolean isForceAuthn) {
            this.isForceAuthenticationEnabled = isForceAuthn;
        }

        public String getRelayState() {
            return relayState;
        }

        public void setRelayState(String relayState) {
            this.relayState = relayState;
        }

        public String getPostBindingRequestHTMLPayload() {
            return postBindingRequestHTMLPayload;
        }

        public void setPostBindingRequestHTMLPayload(String postBindingRequestHTMLPayload) {
            this.postBindingRequestHTMLPayload = postBindingRequestHTMLPayload;
        }

        public String getSignatureValidatorImplClass() {
            return signatureValidatorImplClass;
        }

        private void setSignatureValidatorImplClass(String signatureValidatorImplClass) {
            this.signatureValidatorImplClass = signatureValidatorImplClass;
        }
    }

    /**
     * A nested class which defines the OAuth2 SSO configuration properties.
     */
    public static class OAuth2 {
        private String tokenURL;
        private String clientId;
        private String clientSecret;

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getTokenURL() {
            return tokenURL;
        }

        public void setTokenURL(String tokenURL) {
            this.tokenURL = tokenURL;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }
    }
}
