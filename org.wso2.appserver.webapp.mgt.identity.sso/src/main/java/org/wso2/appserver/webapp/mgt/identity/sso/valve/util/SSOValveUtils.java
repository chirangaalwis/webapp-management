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
package org.wso2.appserver.webapp.mgt.identity.sso.valve.util;

import org.wso2.appserver.webapp.mgt.identity.sso.SSOException;
import org.wso2.appserver.webapp.mgt.identity.sso.valve.SSOValveConstants;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Properties;

/**
 * This class contains utility methods of the implementation of the SAML 2.0 single-sign-on (SSO) valve.
 *
 * @since 6.0.0
 */
public class SSOValveUtils {
    /**
     * Returns a {@code Path} instance representing the Apache Tomcat distribution home.
     *
     * @return a {@link Path} instance representing the Apache Tomcat distribution home
     * @throws SSOException if CATALINA_HOME environmental variable has not been set
     */
    public static Path getTomcatHome() throws SSOException {
        String envVariableValue = System.getProperty(SSOValveConstants.CATALINA_HOME);
        if (Optional.ofNullable(envVariableValue).isPresent()) {
            return Paths.get(envVariableValue);
        } else {
            throw new SSOException("CATALINA_HOME environmental variable has not been set.");
        }
    }

    /**
     * Returns a {@code Path} instance representing the Apache Tomcat configuration home CATALINA_HOME/conf.
     *
     * @return a {@link Path} instance representing the Apache Tomcat configuration home CATALINA_HOME/conf
     * @throws SSOException if CATALINA_HOME environmental variable has not been set
     */
    public static Path getTomcatConfigurationHome() throws SSOException {
        return Paths.get(getTomcatHome().toString(), SSOValveConstants.TOMCAT_CONFIGURATION_FOLDER_NAME);
    }

    /**
     * Returns a unique id value for the SAML 2.0 service provider application based on its context path.
     * </p>
     * An {@code Optional String} id is returned based on the context path provided.
     *
     * @param contextPath the context path of the service provider application
     * @return a unique id value for the SAML 2.0 service provider application based on its context path
     */
    public static Optional generateIssuerID(String contextPath) {
        if (Optional.ofNullable(contextPath).isPresent()) {
            String issuerId = contextPath.replaceFirst("/webapps", "").replace("/", "_");
            if (issuerId.startsWith("_")) {
                issuerId = issuerId.substring(1);
            }
            return Optional.of(issuerId);
        } else {
            return Optional.empty();
        }
    }

    /**
     * Returns a SAML 2.0 Assertion Consumer URL based on service provider application context path.
     * </p>
     * An {@code Optional String} URL is returned based on the context path and configuration properties provided.
     *
     * @param contextPath           the context path of the service provider application
     * @param ssoSPConfigProperties the global single-sign-on configuration properties
     * @return a SAML 2.0 Assertion Consumer URL based on service provider application context path
     */
    public static Optional generateConsumerUrl(String contextPath, Properties ssoSPConfigProperties) {
        if ((Optional.ofNullable(contextPath).isPresent()) && (Optional.ofNullable(ssoSPConfigProperties).
                isPresent())) {
            return Optional.of(ssoSPConfigProperties.getProperty(SSOValveConstants.APP_SERVER_URL) + contextPath +
                    ssoSPConfigProperties.getProperty(SSOValveConstants.CONSUMER_URL_POSTFIX));
        } else {
            return Optional.empty();
        }
    }
}
