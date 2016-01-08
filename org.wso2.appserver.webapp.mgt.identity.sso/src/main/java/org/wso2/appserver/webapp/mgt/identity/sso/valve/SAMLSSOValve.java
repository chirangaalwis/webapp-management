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
package org.wso2.appserver.webapp.mgt.identity.sso.valve;

import org.apache.catalina.authenticator.SingleSignOn;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.wso2.appserver.webapp.mgt.identity.sso.SSOException;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.SSOAgentConstants;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.SSOAgentRequestResolver;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.model.SSOAgentConfiguration;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.saml.SAML2SSOManager;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.util.SSOAgentUtils;
import org.wso2.appserver.webapp.mgt.identity.sso.valve.model.RelayState;
import org.wso2.appserver.webapp.mgt.identity.sso.valve.util.SSOValveUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

/**
 * This class implements an Apache Tomcat valve, which performs SAML 2.0 single-sign-on function.
 * </p>
 * This is a sub-class of the {@code org.apache.catalina.authenticator.SingleSignOn} class.
 *
 * @since 6.0.0
 */
public class SAMLSSOValve extends SingleSignOn {
    private static final Logger logger = Logger.getLogger(SAMLSSOValve.class.getName());

    private Properties ssoSPConfigProperties;

    //  An instance field initialization block
    {
        setSSOSPConfigProperties(new Properties());
    }

    public SAMLSSOValve() throws SSOException {
        getLogger().log(Level.INFO, "Initializing SAMLSSOValve...");

        Path ssoSPConfigFilePath = Paths.
                get(SSOValveUtils.getTomcatConfigurationHome().toString(), SSOValveConstants.SSO_CONFIG_FILE_NAME);

        //  Reads generic SSO ServiceProvider details, if sso-sp-config.properties file exists
        if (Files.exists(ssoSPConfigFilePath)) {
            try (InputStream fileInputStream = Files.newInputStream(ssoSPConfigFilePath)) {
                getSSOSPConfigProperties().load(fileInputStream);
                getLogger().log(Level.INFO, "Successfully loaded global single-sign-on configuration " +
                        "data from sso-sp-config.properties file.");
            } catch (IOException e) {
                throw new SSOException("Error when loading global single-sign-on configuration data " +
                        "from sso-sp-config.properties file.");
            }
        } else {
            throw new SSOException("Unable to find sso-sp-config.properties file in " + ssoSPConfigFilePath);
        }
    }

    private static Logger getLogger() {
        return logger;
    }

    public Properties getSSOSPConfigProperties() {
        return ssoSPConfigProperties;
    }

    private void setSSOSPConfigProperties(Properties ssoSPConfigProperties) {
        this.ssoSPConfigProperties = ssoSPConfigProperties;
    }

    /**
     * Performs single-sign-on processing for this request using SAML 2.0 protocol.
     * </p>
     * This method overrides the parent {@link SingleSignOn} class' invoke() method.
     *
     * @param request  the servlet request processed
     * @param response the servlet response generated
     * @throws IOException      if an input/output error occurs
     * @throws ServletException if a servlet error occurs
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        getLogger().log(Level.FINE, "Invoking SAMLSSOValve. Request URI : " + request.getRequestURI());

        Properties configurationProperties = getSSOSPConfigProperties();

        //  Checks if SAML 2.0 single-sign-on valve is enabled in the context-param
        if (!(Boolean.parseBoolean(request.getContext().findParameter(SSOValveConstants.ENABLE_SAML2_SSO)))) {
            getLogger().log(Level.FINE, "SAML2 SSO not enabled in webapp " + request.getContext().getName());
            //  Moves onto the next valve, if SAML2 SSO valve is not enabled
            getNext().invoke(request, response);
            return;
        }

        SSOAgentConfiguration ssoAgentConfiguration;
        Optional ssoAgent = Optional.ofNullable(request.getSessionInternal().
                getNote(SSOValveConstants.SSO_AGENT_CONFIG));
        if (!ssoAgent.isPresent()) {
            try {
                //  Constructs a new SSOAgentConfiguration instance
                ssoAgentConfiguration = new SSOAgentConfiguration();
                ssoAgentConfiguration.initConfig(configurationProperties);

                //  TODO: user model, X.509 certificate handling

                Optional.of(SSOValveUtils.generateIssuerID(request.getContextPath())).
                        ifPresent(id -> ssoAgentConfiguration.getSAML2().setSPEntityId((String) id.get()));
                Optional.of(SSOValveUtils.generateConsumerUrl(request.getContextPath(), configurationProperties)).
                        ifPresent(url -> ssoAgentConfiguration.getSAML2().setACSURL((String) url.get()));
                ssoAgentConfiguration.verifyConfig();

                request.getSessionInternal().setNote(SSOValveConstants.SSO_AGENT_CONFIG, ssoAgentConfiguration);
            } catch (SSOException e) {
                getLogger().log(Level.SEVERE, "Error on initializing SAML2SSOManager", e);
                return;
            }
        } else {
            ssoAgentConfiguration = (SSOAgentConfiguration) ssoAgent.get();
        }

        SSOAgentRequestResolver requestResolver = new SSOAgentRequestResolver(request, ssoAgentConfiguration);

        //  If the request URL matches one of the URL(s) to skip, moves on to the next valve
        if (requestResolver.isURLToSkip()) {
            getLogger().log(Level.FINE, "Request matched a skip URL. Skipping...");
            getNext().invoke(request, response);
            return;
        }

        SAML2SSOManager saml2SSOManager;
        HttpSession session = request.getSession(false);

        if (requestResolver.isSLORequest()) {

        } else if (requestResolver.isSAML2SSOResponse()) {

            /*if (log.isDebugEnabled()) {
                log.debug("Processing SSO Response.");
            }*/

            saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);

            try {
                // Read the redirect path. This has to read before the session get invalidated as it first
                // tries to read the redirect path form the session attribute
//                String redirectPath = readAndForgetRedirectPathAfterSLO(request);

                saml2SSOManager.processResponse(request);
                //redirect according to relay state attribute
                String relayStateId = ssoAgentConfiguration.getSAML2().getRelayState();
                if (relayStateId != null && request.getSession(Boolean.FALSE) != null) {
                    RelayState relayState = (RelayState) request.getSession(Boolean.FALSE)
                            .getAttribute(relayStateId);
                    if (relayState != null) {
                        request.getSession(Boolean.FALSE).removeAttribute(relayStateId);

                        String requestedURI = relayState.getRequestedURL();
                        if (relayState.getRequestQueryString() != null) {
                            requestedURI = requestedURI.concat("?").concat(relayState.getRequestQueryString());
                        }
                        if (relayState.getRequestParameters() != null) {
                            request.getSession(Boolean.FALSE).setAttribute(SSOValveConstants.REQUEST_PARAM_MAP,
                                    relayState.getRequestParameters());
                        }
                        response.sendRedirect(requestedURI);
                        return;
                    } else {
                        response.sendRedirect(
                                    ssoSPConfigProperties.getProperty(SSOValveConstants.APP_SERVER_URL) + request
                                        .getContextPath());
                        return;
                    }
                }
            } catch (SSOException e) {
                getLogger().log(Level.FINE, "Error in SAML SSO Response processing", e);
            }


        } else if (requestResolver.isSLOURL()) {

        } else if ((requestResolver.isSAML2SSOURL()) || ((!Optional.ofNullable(session).isPresent()) || (!Optional.
                ofNullable(session.getAttribute(SSOAgentConstants.SESSION_BEAN_NAME)).isPresent()))) {
            //  Handles the unauthenticated requests for all contexts
            getLogger().log(Level.FINE, "Processing SSO URL");
            saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);

            String relayStateId = SSOAgentUtils.createID();
            RelayState relayState = new RelayState();
            relayState.setRequestedURL(request.getRequestURI());
            relayState.setRequestQueryString(request.getQueryString());
            relayState.setRequestParameters(request.getParameterMap());
            ssoAgentConfiguration.getSAML2().setRelayState(relayStateId);

            if (Optional.ofNullable(session).isPresent()) {
                session.setAttribute(relayStateId, relayState);
            }

            ssoAgentConfiguration.getSAML2().setPassiveAuthn(false);
            if (requestResolver.isHttpPostBinding()) {
                String htmlPayload = saml2SSOManager.buildPostRequest(request, false);
                SSOAgentUtils.sendCharacterData(response, htmlPayload);
            } else {
                //  TODO: test redirect
//                response.sendRedirect(saml2SSOManager.buildRedirectRequest(request, false));
            }
            return;
        }

        //  Moves onto the next valve
        getNext().invoke(request, response);
    }
}
