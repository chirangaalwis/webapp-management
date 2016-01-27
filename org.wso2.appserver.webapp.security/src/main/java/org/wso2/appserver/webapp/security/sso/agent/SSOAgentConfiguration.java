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
package org.wso2.appserver.webapp.security.sso.agent;

import org.opensaml.common.xml.SAMLConstants;
import org.wso2.appserver.webapp.security.sso.SSOConstants;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.wso2.appserver.webapp.security.sso.SSOUtils;
import org.wso2.appserver.webapp.security.sso.saml.signature.SSOX509Credential;

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
    private static final Logger logger = Logger.getLogger(SSOAgentConfiguration.class.getName());

    private Boolean isSAML2SSOLoginEnabled;
    private String saml2SSOURL;
    private Set<String> skipURIs;
    private Map<String, String[]> queryParameters;
    private SAML2 saml2;

    //  An instance field initialization block
    {
        queryParameters = new HashMap<>();
        skipURIs = new HashSet<>();
        saml2 = new SAML2();
    }

    public Boolean isSAML2SSOLoginEnabled() {
        return isSAML2SSOLoginEnabled;
    }

    public String getSAML2SSOURL() {
        return saml2SSOURL;
    }

    public Set<String> getSkipURIs() {
        return skipURIs;
    }

    public Map<String, String[]> getQueryParameters() {
        return queryParameters;
    }

    public SAML2 getSAML2() {
        return saml2;
    }

    /**
     * Sets up the single-sign-on (SSO) agent configurations based on the {@code properties} defined.
     *
     * @param properties the set of properties to be used to set up the SSO Agent configuration properties
     */
    public void initConfig(Properties properties) {
        Optional.ofNullable(properties).ifPresent(configProperties -> {
            Optional<String> isSAML2SSOLoginEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_SAML2_SSO_LOGIN));
            if (isSAML2SSOLoginEnabledString.isPresent()) {
                isSAML2SSOLoginEnabled = Boolean.parseBoolean(isSAML2SSOLoginEnabledString.get());
            } else {
                logger.log(Level.FINE, SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_SAML2_SSO_LOGIN +
                        " not configured. Defaulting to \'false\'");
                isSAML2SSOLoginEnabled = false;
            }

            saml2SSOURL = configProperties.getProperty(SSOConstants.SSOAgentConfiguration.SAML2.SAML2_SSO_URL);

            String skipURIsString = configProperties.getProperty(SSOConstants.SSOAgentConfiguration.SKIP_URIS);
            if (!SSOUtils.isBlank(skipURIsString)) {
                String[] skipURIArray = skipURIsString.split(",");
                Stream.of(skipURIArray).forEach(skipURIs::add);
            }

            String queryParameterString = configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.QUERY_PARAMS);
            if (!SSOUtils.isBlank(queryParameterString)) {
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
                        queryParameters.put(entry.getKey(), values);
                    });
                });
            }

            saml2.setHttpBinding(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.HTTP_BINDING));
            if ((!Optional.ofNullable(saml2.getHttpBinding()).isPresent()) || saml2.getHttpBinding().
                    isEmpty()) {
                logger.log(Level.FINE, SSOConstants.SSOAgentConfiguration.SAML2.HTTP_BINDING +
                        " not configured. Defaulting to \'" + SAMLConstants.SAML2_POST_BINDING_URI + "\'");
                saml2.setHttpBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            }
            saml2.setSPEntityId(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.SP_ENTITY_ID));
            saml2.setACSURL(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ACS_URL));
            saml2.setIdPEntityId(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.IDP_ENTITY_ID));
            saml2.setIdPURL(configProperties.getProperty(SSOConstants.SSOAgentConfiguration.SAML2.IDP_URL));
            saml2.setAttributeConsumingServiceIndex(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ATTRIBUTE_CONSUMING_SERVICE_INDEX));

            Optional<String> isSLOEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_SLO));
            if (isSLOEnabledString.isPresent()) {
                saml2.setSLOEnabled(Boolean.parseBoolean(isSLOEnabledString.get()));
            } else {
                logger.log(Level.INFO, "\'" + SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_SLO +
                        "\' not configured. Defaulting to \'false\'");
                saml2.setSLOEnabled(false);
            }
            saml2.setSLOURL(configProperties.getProperty(SSOConstants.SSOAgentConfiguration.SAML2.SLO_URL));

            Optional<String> isAssertionSignedString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_SIGNING));
            if (isAssertionSignedString.isPresent()) {
                saml2.setAssertionSigned(Boolean.parseBoolean(isAssertionSignedString.get()));
            } else {
                logger.log(Level.FINE, SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_SIGNING +
                        " not configured. Defaulting to \'false\'");
                saml2.setAssertionSigned(false);
            }

            Optional<String> isAssertionEncryptedString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_ENCRYPTION));
            if (isAssertionEncryptedString.isPresent()) {
                saml2.setAssertionEncrypted(Boolean.parseBoolean(isAssertionEncryptedString.get()));
            } else {
                logger.log(Level.FINE, SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_ASSERTION_ENCRYPTION +
                        " not configured. Defaulting to \'false\'");
                saml2.setAssertionEncrypted(false);
            }

            Optional<String> isResponseSignedString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_RESPONSE_SIGNING));
            if (isResponseSignedString.isPresent()) {
                saml2.setResponseSigned(Boolean.parseBoolean(isResponseSignedString.get()));
            } else {
                logger.log(Level.FINE, SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_RESPONSE_SIGNING +
                        " not configured. Defaulting to \'false\'");
                saml2.setResponseSigned(false);
            }

            if (saml2.isResponseSigned()) {
                Optional<String> signatureValidatorImplClass = Optional.ofNullable(configProperties.
                        getProperty(SSOConstants.SSOAgentConfiguration.SAML2.SIGNATURE_VALIDATOR));
                if (signatureValidatorImplClass.isPresent()) {
                    saml2.setSignatureValidatorImplClass(signatureValidatorImplClass.get());
                } else {
                    logger.log(Level.FINE,
                            SSOConstants.SSOAgentConfiguration.SAML2.SIGNATURE_VALIDATOR + " not configured");
                }
            }

            Optional<String> isRequestSignedString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_REQUEST_SIGNING));
            if (isRequestSignedString.isPresent()) {
                saml2.setRequestSigned(Boolean.parseBoolean(isRequestSignedString.get()));
            } else {
                logger.log(Level.FINE, SSOConstants.SSOAgentConfiguration.SAML2.ENABLE_REQUEST_SIGNING +
                        " not configured. Defaulting to \'false\'");
                saml2.setRequestSigned(false);
            }

            Optional<String> isPassiveAuthenticationEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.IS_PASSIVE_AUTHN));
            if (isPassiveAuthenticationEnabledString.isPresent()) {
                saml2.setPassiveAuthn(Boolean.parseBoolean(isPassiveAuthenticationEnabledString.get()));
            } else {
                logger.log(Level.FINE, "\'" + SSOConstants.SSOAgentConfiguration.SAML2.IS_PASSIVE_AUTHN +
                        "\' not configured. Defaulting to \'false\'");
                saml2.setPassiveAuthn(false);
            }

            Optional<String> isForceAuthenticationEnabledString = Optional.ofNullable(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.IS_FORCE_AUTHN));
            if (isForceAuthenticationEnabledString.isPresent()) {
                saml2.setForceAuthn(Boolean.parseBoolean(isForceAuthenticationEnabledString.get()));
            } else {
                logger.log(Level.FINE, "\'" + SSOConstants.SSOAgentConfiguration.SAML2.IS_FORCE_AUTHN +
                        "\' not configured. Defaulting to \'false\'");
                saml2.setForceAuthn(false);
            }

            saml2.setRelayState(configProperties.getProperty(SSOConstants.SSOAgentConfiguration.SAML2.RELAY_STATE));
            saml2.setPostBindingRequestHTMLPayload(configProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.POST_BINDING_REQUEST_HTML_PAYLOAD));
        });
    }

    /**
     * Verifies the validity of single-sign-on (SSO) agent configurations at the current state of this
     * {@code SSOAgentConfiguration} instance.
     *
     * @throws SSOException if the relevant configurations are invalidly set at the current state of the
     *                      SSOAgentConfiguration instance
     */
    public void verifyConfig() throws SSOException {
        if (isSAML2SSOLoginEnabled && (!Optional.ofNullable(saml2SSOURL).isPresent())) {
            throw new SSOException("\'" +
                    SSOConstants.SSOAgentConfiguration.SAML2.SAML2_SSO_URL + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled && (!Optional.ofNullable(saml2.getSPEntityId()).isPresent())) {
            throw new SSOException("\'" +
                    SSOConstants.SSOAgentConfiguration.SAML2.SP_ENTITY_ID + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled && (!Optional.ofNullable(saml2.getACSURL()).isPresent())) {
            throw new SSOException("\'" +
                    SSOConstants.SSOAgentConfiguration.SAML2.ACS_URL + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled && (!Optional.ofNullable(saml2.getIdPEntityId()).isPresent())) {
            throw new SSOException("\'" +
                    SSOConstants.SSOAgentConfiguration.SAML2.IDP_ENTITY_ID + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled && (!Optional.ofNullable(saml2.getIdPURL()).isPresent())) {
            throw new SSOException("\'" +
                    SSOConstants.SSOAgentConfiguration.SAML2.IDP_URL + "\' not configured.");
        }

        if (isSAML2SSOLoginEnabled && (!Optional.ofNullable(saml2.getAttributeConsumingServiceIndex()).
                isPresent())) {
            logger.log(Level.FINE, "\'" + SSOConstants.SSOAgentConfiguration.SAML2.ATTRIBUTE_CONSUMING_SERVICE_INDEX +
                            "\' not configured. No attributes of the Subject will be requested.");
        }

        if (isSAML2SSOLoginEnabled && saml2.isSLOEnabled() && (!Optional.ofNullable(saml2.
                getSLOURL()).isPresent())) {
            throw new SSOException("Single Logout enabled, but SLO URL not configured.");
        }

        if (isSAML2SSOLoginEnabled &&
                (saml2.isAssertionSigned() || saml2.isAssertionEncrypted() || saml2.isResponseSigned() ||
                        saml2.isRequestSigned()) &&
                (!Optional.ofNullable(saml2.getSSOAgentX509Credential()).isPresent())) {
            logger.log(Level.FINE,
                    "\'SSOX509Credential\' not configured. Defaulting to " + SSOX509Credential.class.getName());
        }

        if (isSAML2SSOLoginEnabled &&
                (saml2.isAssertionSigned() || saml2.isResponseSigned()) &&
                (!Optional.ofNullable(saml2.getSSOAgentX509Credential().getEntityCertificate()).isPresent())) {
            throw new SSOException("Public certificate of IdP not configured.");
        }

        if (isSAML2SSOLoginEnabled &&
                (saml2.isRequestSigned() || saml2.isAssertionEncrypted()) &&
                (!Optional.ofNullable(saml2.getSSOAgentX509Credential().getPrivateKey()).isPresent())) {
            throw new SSOException("Private key of SP not configured.");
        }
    }

    /**
     * A nested class which defines the SAML 2.0 single-sign-on (SSO) configuration properties.
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
        private SSOX509Credential ssoX509Credential;
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

        public SSOX509Credential getSSOAgentX509Credential() {
            return ssoX509Credential;
        }

        public void setSSOAgentX509Credential(SSOX509Credential ssoAgentX509Credential) {
            this.ssoX509Credential = ssoAgentX509Credential;
        }

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
}
