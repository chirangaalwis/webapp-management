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

import org.wso2.appserver.webapp.mgt.identity.sso.SSOException;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * This class contains utility methods of the implementation of the SAML 2.0 single-sign-on valve.
 *
 * @since 6.0.0
 */
public class SSOUtils {
    /**
     * Returns a {@code Path} instance representing the Apache Tomcat distribution home.
     *
     * @return a {@link Path} instance representing the Apache Tomcat distribution home
     * @throws SSOException if CATALINA_HOME environmental variable has not been set
     */
    public static Path getTomcatHome() throws SSOException {
        String envVariableValue = System.getProperty(WebappSSOConstants.CATALINA_HOME);
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
        return Paths.get(getTomcatHome().toString(), WebappSSOConstants.TOMCAT_CONFIGURATION_FOLDER_NAME);
    }
}
