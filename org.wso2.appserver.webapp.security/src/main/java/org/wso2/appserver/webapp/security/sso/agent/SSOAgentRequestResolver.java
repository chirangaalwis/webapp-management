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

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.appserver.webapp.security.sso.SSOConstants;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

/**
 * This class provides an implementation for resolving the type of an intercepted HTTP servlet request by analyzing
 * the single-sign-on (SSO) agent configuration data and HTTP servlet request.
 *
 * @since 6.0.0
 */
public class SSOAgentRequestResolver {
    private SSOAgentConfiguration ssoAgentConfiguration;
    private HttpServletRequest request;

    public SSOAgentRequestResolver(HttpServletRequest request, SSOAgentConfiguration ssoAgentConfiguration) {
        this.ssoAgentConfiguration = ssoAgentConfiguration;
        this.request = request;
    }

    /**
     * Returns true if request URI matches the globally configured URL to send SAML 2.0 single-sign-on (SSO)
     * authentication request(s), else false.
     *
     * @return true if request URI matches the globally configured URL to send SAML 2.0 single-sign-on (SSO)
     * authentication request(s), else false
     */
    public boolean isSAML2SSOURL() {
        return (ssoAgentConfiguration.isSAML2SSOLoginEnabled()) && (request.getRequestURI().
                endsWith(ssoAgentConfiguration.getSAML2SSOURL()));
    }

    /**
     * Returns true if request corresponds to a SAML 2.0 Response for a SAML 2.0 single-sign-on (SSO) authentication
     * request by the service provider or to a SAML 2.0 Response for a SAML 2.0 single-logout (SLO) request from the
     * service provider.
     *
     * @return true if request corresponds to a SAML 2.0 Response for a SAML 2.0 single-sign-on (SSO) authentication
     * request by the service provider or to a SAML 2.0 Response for a SAML 2.0 single-logout (SLO) request from the
     * service provider
     */
    public boolean isSAML2SSOResponse() {
        return (ssoAgentConfiguration.isSAML2SSOLoginEnabled()) && (Optional.ofNullable(request.
                getParameter(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_RESPONSE)).isPresent());
    }

    /**
     * Returns true if the request is an identity provider initiated SAML 2.0 single-logout (SLO) request, else false.
     *
     * @return true if the request is an identity provider initiated SAML 2.0 single-logout (SLO) request, else false
     */
    public boolean isSAML2SLORequest() {
        return (ssoAgentConfiguration.isSAML2SSOLoginEnabled()) && (Optional.ofNullable(request.
                getParameter(AuthnRequest.DEFAULT_ELEMENT_LOCAL_NAME)).isPresent());
    }

    /**
     * Returns true if the request URI matches globally configured URL for sending session participant initiated
     * SAML 2.0 single-logout (SLO) request(s), else false.
     *
     * @return true if the request URI matches globally configured URL for sending session participant initiated
     * SAML 2.0 single-logout (SLO) request(s), else false
     */
    public boolean isSLOURL() {
        return (ssoAgentConfiguration.isSAML2SSOLoginEnabled()) &&
                (ssoAgentConfiguration.getSAML2().isSLOEnabled()) &&
                (request.getRequestURI().endsWith(ssoAgentConfiguration.getSAML2().getSLOURL()));
    }

    /**
     * Returns true if SAML 2.0 binding is HTTP POST type binding, else false.
     *
     * @return true if SAML 2.0 binding is HTTP POST type binding, else false
     */
    public boolean isHttpPostBinding() {
        String httpBindingString = ssoAgentConfiguration.getSAML2().getHttpBinding();
        return (Optional.ofNullable(httpBindingString).isPresent()) && (SAMLConstants.SAML2_POST_BINDING_URI.
                equals(httpBindingString));
    }

    /**
     * Returns true if the request URI is one of the URI(s) to be skipped as specified by global configuration
     * property SkipURIs, else returns false.
     *
     * @return true if the request URI is one of the URI(s) to be skipped as specified by global configuration
     * property SkipURIs, else returns false
     */
    public boolean isURLToSkip() {
        return ssoAgentConfiguration.getSkipURIs().contains(request.getRequestURI());
    }
}
