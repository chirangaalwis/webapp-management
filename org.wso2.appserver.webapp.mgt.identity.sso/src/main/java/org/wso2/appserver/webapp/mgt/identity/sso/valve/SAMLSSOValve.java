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
import org.wso2.appserver.webapp.mgt.identity.sso.agent.bean.SSOAgentConfiguration;

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
        logger.log(Level.INFO, "Initializing SAMLSSOValve...");

        Path ssoSPConfigFilePath = Paths.
                get(SSOUtils.getTomcatConfigurationHome().toString(), WebappSSOConstants.SSO_CONFIG_FILE_NAME);

        //  Reads generic SSO ServiceProvider details, if sso-sp-config.properties file exists
        if (Files.exists(ssoSPConfigFilePath)) {
            try (InputStream fileInputStream = Files.newInputStream(ssoSPConfigFilePath)) {
                getSSOSPConfigProperties().load(fileInputStream);
                logger.log(Level.INFO, "Successfully loaded global single-sign-on configuration " +
                        "data from sso-sp-config.properties file.");
            } catch (IOException e) {
                throw new SSOException("Error when loading global single-sign-on configuration data " +
                        "from sso-sp-config.properties file.");
            }
        } else {
            throw new SSOException("Unable to find sso-sp-config.properties file in " + ssoSPConfigFilePath);
        }
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
     * @param request  The servlet request processed
     * @param response The servlet response generated
     * @throws IOException      if an input/output error occurs
     * @throws ServletException if a servlet error occurs
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        logger.log(Level.FINE, "Invoking SAMLSSOValve. Request URI : " + request.getRequestURI());

        Properties configurationProperties = getSSOSPConfigProperties();

        //  Checks if SAML 2.0 single-sign-on valve is enabled in the context-param
        if (!(Boolean.parseBoolean(request.getContext().findParameter(WebappSSOConstants.ENABLE_SAML2_SSO)))) {
            logger.log(Level.FINE, "SAML2 SSO not enabled in webapp " + request.getContext().getName());
            //  Moves onto the next valve, if SAML2 SSO valve is not enabled
            getNext().invoke(request, response);
            return;
        }

        SSOAgentConfiguration ssoAgentConfiguration;
        Optional ssoAgent = Optional.ofNullable(request.getSessionInternal().
                getNote(WebappSSOConstants.SSO_AGENT_CONFIG));
        if (!ssoAgent.isPresent()) {
            try {
                //  Construct a new SSOAgentConfiguration instance
                ssoAgentConfiguration = new SSOAgentConfiguration();
                ssoAgentConfiguration.initConfig(configurationProperties);

                //  TODO: user model, X.509 certificate handling

                Optional.ofNullable(SSOUtils.generateIssuerID(request.getContextPath())).
                        ifPresent(ssoAgentConfiguration.getSAML2()::setSPEntityId);
                Optional.ofNullable(SSOUtils.generateConsumerUrl(request.getContextPath(), configurationProperties)).
                        ifPresent(ssoAgentConfiguration.getSAML2()::setACSURL);
                ssoAgentConfiguration.verifyConfig();

                request.getSessionInternal().setNote(WebappSSOConstants.SSO_AGENT_CONFIG, ssoAgentConfiguration);
            } catch (SSOException e) {
                logger.log(Level.SEVERE, "Error on initializing SAML2SSOManager", e);
                return;
            }
        } else {
            ssoAgentConfiguration = (SSOAgentConfiguration) ssoAgent.get();
        }

        logger.log(Level.FINE, ssoAgentConfiguration.getOAuth2SAML2GrantURL());

        //  Moves onto the next valve
        getNext().invoke(request, response);
    }
}
