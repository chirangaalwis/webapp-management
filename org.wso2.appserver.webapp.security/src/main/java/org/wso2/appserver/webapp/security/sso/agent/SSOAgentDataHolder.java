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

public class SSOAgentDataHolder {
    private Object signatureValidator = null;

    private static SSOAgentDataHolder instance = new SSOAgentDataHolder();

    private SSOAgentDataHolder() {
    }

    public Object getSignatureValidator() {
        return signatureValidator;
    }

    public void setSignatureValidator(Object signatureValidator) {
        this.signatureValidator = signatureValidator;
    }

    public static SSOAgentDataHolder getInstance() {
        return instance;
    }
}
