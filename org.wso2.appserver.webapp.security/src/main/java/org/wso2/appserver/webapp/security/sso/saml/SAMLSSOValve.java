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
package org.wso2.appserver.webapp.security.sso.saml;

import org.apache.catalina.authenticator.SingleSignOn;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.wso2.appserver.webapp.security.sso.SSOConstants;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.wso2.appserver.webapp.security.sso.SSOUtils;
import org.wso2.appserver.webapp.security.sso.agent.SSOAgentConfiguration;
import org.wso2.appserver.webapp.security.sso.agent.SSOAgentRequestResolver;
import org.wso2.appserver.webapp.security.sso.bean.RelayState;
import org.wso2.appserver.webapp.security.sso.saml.signature.SSOX509Credential;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;

/**
 * This class implements an Apache Tomcat valve, which performs SAML 2.0 based single-sign-on (SSO) function.
 * <p>
 * This is a sub-class of the {@code org.apache.catalina.authenticator.SingleSignOn} class.
 *
 * @since 6.0.0
 */
public class SAMLSSOValve extends SingleSignOn {
    private static final Logger logger = Logger.getLogger(SAMLSSOValve.class.getName());

    private Properties ssoSPConfigProperties;

    //  An instance field initialization block
    {
        ssoSPConfigProperties = new Properties();
    }

    public SAMLSSOValve() throws SSOException {
        logger.log(Level.INFO, "Initializing SAMLSSOValve...");

        Path ssoSPConfigFilePath = Paths.
                get(SSOUtils.getCatalinaConfigurationHome().toString(),
                        SSOConstants.SAMLSSOValveConstants.SSO_CONFIG_FILE_NAME);
        //  Reads generic SSO ServiceProvider details, if sso-sp-config.properties file exists
        SSOUtils.loadPropertiesFromFile(ssoSPConfigProperties, ssoSPConfigFilePath);
    }

    /**
     * Performs single-sign-on (SSO) processing for this request using SAML 2.0 protocol.
     * <p>
     * This method overrides the parent {@link SingleSignOn} class' invoke() method.
     *
     * @param request  the servlet request processed
     * @param response the servlet response generated
     * @throws IOException      if an input/output error occurs
     * @throws ServletException if a servlet error occurs
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        logger.log(Level.FINE, "Invoking SAMLSSOValve. Request URI : " + request.getRequestURI());

        //  Checks if single-sign-on feature is enabled
        if ((request.getRequest().getRequestURI().equals("/")) || ((!SSOUtils.singleSignOnEnabled()))) {
            logger.log(Level.FINE, "SAML2 SSO not enabled in webapp " + request.getContext().getName());
            //  Moves onto the next valve, if single-sign-on is not enabled
            getNext().invoke(request, response);
            return;
        }

        SSOAgentConfiguration ssoAgentConfiguration;
        Optional ssoAgent = Optional.ofNullable(request.getSessionInternal().
                getNote(SSOConstants.SAMLSSOValveConstants.SSO_AGENT_CONFIG));
        if (!ssoAgent.isPresent()) {
            try {
                //  Constructs a new SSOAgentConfiguration instance
                ssoAgentConfiguration = new SSOAgentConfiguration();
                ssoAgentConfiguration.initConfig(ssoSPConfigProperties);

                ssoAgentConfiguration.getSAML2().
                        setSSOAgentX509Credential(new SSOX509Credential(ssoSPConfigProperties));
                Optional.of(SAMLSSOUtils.generateIssuerID(request.getContextPath())).
                        ifPresent(id -> ssoAgentConfiguration.getSAML2().setSPEntityId((String) id.get()));
                Optional.of(SAMLSSOUtils.generateConsumerUrl(request.getContextPath(), ssoSPConfigProperties)).
                        ifPresent(url -> ssoAgentConfiguration.getSAML2().setACSURL((String) url.get()));
                ssoAgentConfiguration.verifyConfig();

                request.getSessionInternal().
                        setNote(SSOConstants.SAMLSSOValveConstants.SSO_AGENT_CONFIG, ssoAgentConfiguration);
            } catch (SSOException e) {
                logger.log(Level.SEVERE, "Error on initializing SAML2SSOManager", e);
                return;
            }
        } else {
            ssoAgentConfiguration = (SSOAgentConfiguration) ssoAgent.get();
        }

        try {
            SSOAgentRequestResolver requestResolver = new SSOAgentRequestResolver(request, ssoAgentConfiguration);

            //  If the request URL matches one of the URL(s) to skip, moves on to the next valve
            if (requestResolver.isURLToSkip()) {
                logger.log(Level.FINE, "Request matched a skip URL. Skipping...");
                getNext().invoke(request, response);
                return;
            }

            SAML2SSOManager saml2SSOManager;
            if (requestResolver.isSAML2SLORequest()) {
                //  Handles single logout request from the identity provider
                logger.log(Level.FINE, "Processing Single Log Out Request...");
                saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);
                saml2SSOManager.performSingleLogout(request);
            } else if (requestResolver.isSAML2SSOResponse()) {
                //  Handles single-sign-on responses during the process
                logger.log(Level.FINE, "Processing SSO Response...");
                saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);

                //  Reads the redirect path. This has to read before the session get invalidated as it first
                //  tries to read the redirect path from the session attribute
                String redirectPath = saml2SSOManager.
                        readAndForgetRedirectPathAfterSLO(request, ssoSPConfigProperties.
                                        getProperty(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO));

                saml2SSOManager.processResponse(request);
                //  Redirect according to relay state attribute
                String relayStateId = ssoAgentConfiguration.getSAML2().getRelayState();
                if ((Optional.ofNullable(relayStateId).isPresent()) && (Optional.ofNullable(request.getSession(false)).
                        isPresent())) {
                    Optional<RelayState> relayState = Optional.
                            ofNullable((RelayState) request.getSession(false).getAttribute(relayStateId));
                    if (relayState.isPresent()) {
                        request.getSession(false).removeAttribute(relayStateId);
                        StringBuilder requestedURI = new StringBuilder(relayState.get().getRequestedURL());
                        Optional.ofNullable(relayState.get().getRequestQueryString()).
                                ifPresent(queryString -> requestedURI.append("?").append(queryString));
                        Optional.ofNullable(relayState.get().getRequestParameters()).
                                ifPresent(queryParameters -> request.getSession(false).
                                        setAttribute(SSOConstants.SAMLSSOValveConstants.REQUEST_PARAM_MAP,
                                                relayState.get().getRequestParameters()));
                        response.sendRedirect(requestedURI.toString());
                    } else {
                        response.sendRedirect(ssoSPConfigProperties.getProperty(
                                SSOConstants.SAMLSSOValveConstants.APP_SERVER_URL) + request.getContextPath());
                    }
                } else if (request.getRequestURI().endsWith(ssoSPConfigProperties.
                        getProperty(SSOConstants.SSOAgentConfiguration.SAML2.CONSUMER_URL_POSTFIX)) && Boolean.
                        parseBoolean(ssoSPConfigProperties.
                                getProperty(SSOConstants.SAMLSSOValveConstants.HANDLE_CONSUMER_URL_AFTER_SLO))) {
                    //  Handling redirect from acs page after SLO response. This will be done if
                    //  SAMLSSOValveConstants.HANDLE_CONSUMER_URL_AFTER_SLO is defined
                    //  SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO value is used determine the redirect path
                    response.sendRedirect(redirectPath);
                }
                return;
            } else if (requestResolver.isSLOURL()) {
                //  Handles single logout request initiated directly at the service provider
                logger.log(Level.FINE, "Processing Single Log Out URL...");
                saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);
                if (requestResolver.isHttpPostBinding()) {
                    if (Optional.ofNullable(request.getSession(false).getAttribute(SSOConstants.SESSION_BEAN_NAME)).
                            isPresent()) {
                        ssoAgentConfiguration.getSAML2().setPassiveAuthn(false);
                        String htmlPayload = saml2SSOManager.buildPostRequest(request, true);
                        saml2SSOManager.sendCharacterData(response, htmlPayload);
                    } else {
                        logger.log(Level.WARNING, "Attempt to logout from a already logout session.");
                        response.sendRedirect(request.getContext().getPath());
                    }
                } else {
                    ssoAgentConfiguration.getSAML2().setPassiveAuthn(false);
                    response.sendRedirect(saml2SSOManager.buildRedirectRequest(request, true));
                }
                return;
            } else if ((requestResolver.isSAML2SSOURL()) || (
                    (!Optional.ofNullable(request.getSession(false)).isPresent()) || (!Optional.
                            ofNullable(request.getSession(false).getAttribute(SSOConstants.SESSION_BEAN_NAME)).
                            isPresent()))) {
                //  Handles the unauthenticated requests for all contexts
                logger.log(Level.FINE, "Processing SSO URL...");
                saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);

                String relayStateId = SSOUtils.createID();
                RelayState relayState = new RelayState();
                relayState.setRequestedURL(request.getRequestURI());
                relayState.setRequestQueryString(request.getQueryString());
                relayState.setRequestParameters(request.getParameterMap());
                ssoAgentConfiguration.getSAML2().setRelayState(relayStateId);

                Optional.ofNullable(request.getSession(false)).
                        ifPresent(httpSession -> httpSession.setAttribute(relayStateId, relayState));

                ssoAgentConfiguration.getSAML2().setPassiveAuthn(false);
                if (requestResolver.isHttpPostBinding()) {
                    String htmlPayload = saml2SSOManager.buildPostRequest(request, false);
                    saml2SSOManager.sendCharacterData(response, htmlPayload);
                } else {
                    response.sendRedirect(saml2SSOManager.buildRedirectRequest(request, false));
                }
                return;
            }

        } catch (SSOException e) {
            logger.log(Level.SEVERE, "An error has occurred", e);
            throw e;
        }

        logger.log(Level.FINE, "End of SAMLSSOValve invoke.");

        //  Moves onto the next valve
        getNext().invoke(request, response);
    }
}
