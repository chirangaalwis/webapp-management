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
import org.wso2.appserver.webapp.security.sso.agent.SSOAgentRequestResolver;
import org.wso2.appserver.webapp.security.sso.model.SSOAgentConfiguration;
import org.wso2.appserver.webapp.security.sso.util.SSOUtils;
import org.wso2.appserver.webapp.security.sso.model.RelayState;

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
 * This class implements an Apache Tomcat valve, which performs SAML 2.0 based single-sign-on (SSO) function.
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
                get(SSOUtils.getTomcatConfigurationHome().toString(),
                        SSOConstants.SAMLSSOValveConstants.SSO_CONFIG_FILE_NAME);

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
     * Performs single-sign-on (SSO) processing for this request using SAML 2.0 protocol.
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
        getLogger().log(Level.FINE, "Invoking SAMLSSOValve. Request URI : " + request.getRequestURI() + ".");

        //  Checks if SAML 2.0 single-sign-on valve is enabled in the context-param
        if (!(Boolean.parseBoolean(
                request.getContext().findParameter(SSOConstants.SAMLSSOValveConstants.ENABLE_SAML2_SSO)))) {
            getLogger().log(Level.FINE, "SAML2 SSO not enabled in webapp " + request.getContext().getName() + ".");
            //  Moves onto the next valve, if SAML2 SSO valve is not enabled
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
                ssoAgentConfiguration.initConfig(getSSOSPConfigProperties());

                //  TODO: user model, X.509 certificate handling

                Optional.of(SSOUtils.generateIssuerID(request.getContextPath())).
                        ifPresent(id -> ssoAgentConfiguration.getSAML2().setSPEntityId((String) id.get()));
                Optional.of(SSOUtils.generateConsumerUrl(request.getContextPath(), getSSOSPConfigProperties())).
                        ifPresent(url -> ssoAgentConfiguration.getSAML2().setACSURL((String) url.get()));
                ssoAgentConfiguration.verifyConfig();

                request.getSessionInternal().
                        setNote(SSOConstants.SAMLSSOValveConstants.SSO_AGENT_CONFIG, ssoAgentConfiguration);
            } catch (SSOException e) {
                getLogger().log(Level.SEVERE, "Error on initializing SAML2SSOManager.", e);
                return;
            }
        } else {
            ssoAgentConfiguration = (SSOAgentConfiguration) ssoAgent.get();
        }

        try {
            SSOAgentRequestResolver requestResolver = new SSOAgentRequestResolver(request, ssoAgentConfiguration);

            //  If the request URL matches one of the URL(s) to skip, moves on to the next valve
            if (requestResolver.isURLToSkip()) {
                getLogger().log(Level.FINE, "Request matched a skip URL. Skipping...");
                getNext().invoke(request, response);
                return;
            }

            SAML2SSOManager saml2SSOManager;

            if (requestResolver.isSAML2SLORequest()) {
                //  Handles single logout request from the identity provider
                getLogger().log(Level.FINE, "Processing Single Log Out Request...");
                saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);
                saml2SSOManager.performSingleLogout(request);
            } else if (requestResolver.isSAML2SSOResponse()) {
                //  Handles single-sign-on responses during the process
                getLogger().log(Level.FINE, "Processing SSO Response...");
                saml2SSOManager = new SAML2SSOManager(ssoAgentConfiguration);

                //  Reads the redirect path. This has to read before the session get invalidated as it first
                //  tries to read the redirect path from the session attribute.
                String redirectPath = readAndForgetRedirectPathAfterSLO(request);

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
                        response.sendRedirect(getSSOSPConfigProperties().getProperty(
                                SSOConstants.SAMLSSOValveConstants.APP_SERVER_URL) + request.getContextPath());
                    }
                } else if (request.getRequestURI().endsWith(
                        getSSOSPConfigProperties().getProperty(SSOConstants.SAMLSSOValveConstants.CONSUMER_URL_POSTFIX))
                        && Boolean.parseBoolean(getSSOSPConfigProperties().
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
                        SSOUtils.sendCharacterData(response, htmlPayload);
                    } else {
                        getLogger().log(Level.WARNING, "Attempt to logout from a already logout session.");
                        response.sendRedirect(request.getContext().getPath());
                    }
                } else {
                    //  If "SSOConstants.HTTP_BINDING_PARAM" is not defined, default to redirect
                    //  TODO: TO BE TESTED
                    ssoAgentConfiguration.getSAML2().setPassiveAuthn(false);
                    response.sendRedirect(saml2SSOManager.buildRedirectRequest(request, true));
                }
                return;
            } else if ((requestResolver.isSAML2SSOURL()) || (
                    (!Optional.ofNullable(request.getSession(false)).isPresent()) || (!Optional.
                            ofNullable(request.getSession(false).getAttribute(SSOConstants.SESSION_BEAN_NAME)).
                            isPresent()))) {
                //  Handles the unauthenticated requests for all contexts
                getLogger().log(Level.FINE, "Processing SSO URL...");
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
                    SSOUtils.sendCharacterData(response, htmlPayload);
                } else {
                    //  TODO: test redirect
                    response.sendRedirect(saml2SSOManager.buildRedirectRequest(request, false));
                }
                return;
            }

        } catch (SSOException e) {
            getLogger().log(Level.SEVERE, "An error has occurred", e);
            throw e;
        }

        getLogger().log(Level.FINE, "End of SAMLSSOValve invoke.");

        //  Moves onto the next valve
        getNext().invoke(request, response);
    }

    /**
     * Returns the redirect path after single-logout (SLO), read from the {@code request}.
     * </p>
     * If the redirect path is read from session then it is removed. Priority order of reading the redirect path is from
     * the Session, Context and Config, respectively.
     *
     * @param request the HTTP servlet request
     * @return redirect path relative to the current application path
     */
    private String readAndForgetRedirectPathAfterSLO(Request request) {
        Optional<String> redirectPath = Optional.empty();
        HttpSession session = request.getSession(false);

        if (Optional.ofNullable(session).isPresent()) {
            redirectPath = Optional.ofNullable(
                    (String) session.getAttribute(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO));
            session.removeAttribute(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO);
        }

        if (!redirectPath.isPresent()) {
            redirectPath = Optional.ofNullable(
                    request.getContext().findParameter(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO));
        }

        if (!redirectPath.isPresent()) {
            redirectPath = Optional.ofNullable(
                    getSSOSPConfigProperties().getProperty(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO));
        }

        if ((redirectPath.isPresent()) && (!redirectPath.get().isEmpty())) {
            redirectPath = Optional.ofNullable(request.getContext().getPath().concat(redirectPath.get()));
        } else {
            redirectPath = Optional.ofNullable(request.getContext().getPath());
        }

        getLogger().log(Level.FINE, "Redirect path = " + redirectPath);

        return redirectPath.get();
    }
}
