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
package org.wso2.appserver.webapp.security.sso.util;

/**
 * This is a singleton class which acts as a holder for an {@code Object} instance during the duration of the
 * single-sign-on (SSO) process.
 *
 * @since 6.0.0
 */
public class SSOAgentDataHolder {
    private static SSOAgentDataHolder instance;

    private Object object;

    //  a static initialization block
    static {
        setInstance(new SSOAgentDataHolder());
    }

    /**
     * Prevents instantiating the SSOAgentDataHolder class.
     */
    private SSOAgentDataHolder() {
    }

    public Object getObject() {
        return object;
    }

    public void setObject(Object object) {
        this.object = object;
    }

    public static SSOAgentDataHolder getInstance() {
        return instance;
    }

    private static void setInstance(SSOAgentDataHolder instance) {
        SSOAgentDataHolder.instance = instance;
    }
}