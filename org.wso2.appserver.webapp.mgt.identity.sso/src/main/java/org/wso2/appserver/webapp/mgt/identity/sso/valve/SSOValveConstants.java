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

/**
 * This class defines constants used in the implementation of the SAML 2.0 single-sign-on (SSO) valve.
 *
 * @since 6.0.0
 */
public class SSOValveConstants {
    //  environmental variable property name constant
    public static final String CATALINA_HOME = "catalina.home";
    //  context parameter property name constant
    public static final String ENABLE_SAML2_SSO = "enable.saml2.sso";
    //  file path related constants
    public static final String SSO_CONFIG_FILE_NAME = "sso-sp-config.properties";
    public static final String TOMCAT_CONFIGURATION_FOLDER_NAME = "conf";
    //  http servlet request session notes' property name and attribute name constants
    public static final String SSO_AGENT_CONFIG = "SSOAgentConfig";
    public static final String REQUEST_PARAM_MAP = "REQUEST_PARAM_MAP";
    //  sso configuration property name constants
    public static final String APP_SERVER_URL = "ApplicationServerURL";
    public static final String CONSUMER_URL_POSTFIX = "SAML.ConsumerUrlPostFix";
    public static final String HANDLE_CONSUMER_URL_AFTER_SLO = "handleConsumerURLAfterSLO";

    public static final String REDIRECT_PATH_AFTER_SLO = "redirectPathAfterSLO";

    /**
     * Prevents instantiating this class.
     */
    private SSOValveConstants() {
    }
}
