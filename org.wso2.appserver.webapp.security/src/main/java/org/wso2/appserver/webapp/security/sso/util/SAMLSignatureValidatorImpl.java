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

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.wso2.appserver.webapp.security.sso.agent.SSOAgentConfiguration;
import org.wso2.appserver.webapp.security.sso.saml.X509CredentialImpl;

public class SAMLSignatureValidatorImpl implements SAMLSignatureValidator {

    @Override
    public void validateSignature(Response response, Assertion assertion, SSOAgentConfiguration ssoAgentConfig)
            throws SSOException {

        if (ssoAgentConfig.getSAML2().isResponseSigned()) {
            if (response.getSignature() == null) {
                throw new SSOException(
                        "SAML2 Response signing is enabled, but signature element not found in SAML2 Response element");
            } else {
                try {
                    SignatureValidator validator = new SignatureValidator(new X509CredentialImpl(
                            ssoAgentConfig.getSAML2().getSSOAgentX509Credential().getEntityCertificate()));
                    validator.validate(response.getSignature());
                } catch (ValidationException e) {
                    throw new SSOException("Signature validation failed for SAML2 Response");
                }
            }
        }
        if (ssoAgentConfig.getSAML2().isAssertionSigned()) {
            if (assertion.getSignature() == null) {
                throw new SSOException(
                        "SAML2 Assertion signing is enabled, but signature element not found in SAML2 Assertion element");
            } else {
                try {
                    SignatureValidator validator = new SignatureValidator(new X509CredentialImpl(
                            ssoAgentConfig.getSAML2().getSSOAgentX509Credential().getEntityCertificate()));
                    validator.validate(response.getSignature());
                } catch (ValidationException e) {
                    throw new SSOException("Signature validation failed for SAML2 Assertion");
                }
            }
        }
    }
}