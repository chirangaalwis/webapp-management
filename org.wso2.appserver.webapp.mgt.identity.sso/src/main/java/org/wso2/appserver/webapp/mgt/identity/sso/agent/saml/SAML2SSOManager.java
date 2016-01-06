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
package org.wso2.appserver.webapp.mgt.identity.sso.agent.saml;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;
import org.wso2.appserver.webapp.mgt.identity.sso.SSOException;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.SSOAgentConstants;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.model.SSOAgentConfiguration;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.util.SSOAgentUtils;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;

/**
 * This class manages the generation of varied request and response types that are utilized
 * within the SAML 2.0 single-sign-on process.
 */
public class SAML2SSOManager {
    private SSOAgentConfiguration ssoAgentConfiguration;

    public SAML2SSOManager(SSOAgentConfiguration ssoAgentConfiguration) throws SSOException {
        setSSOAgentConfig(ssoAgentConfiguration);
        //  TODO: uncomment later
//        loadCustomSignatureValidatorClass();
        SSOAgentUtils.doBootstrap();
    }

    private void setSSOAgentConfig(SSOAgentConfiguration ssoAgentConfiguration) {
        this.ssoAgentConfiguration = ssoAgentConfiguration;
    }

    public SSOAgentConfiguration getSSOAgentConfig() {
        return ssoAgentConfiguration;
    }

    /**
     * Handles the request for HTTP POST binding.
     *
     * @param request  the HTTP Servlet request with SAML 2.0 message
     * @param isLogout true if request is a logout request, else false
     * @return the HTML payload to be transmitted
     * @throws SSOException if SSO session is null
     */
    public String buildPostRequest(HttpServletRequest request, boolean isLogout) throws SSOException {
        //  Parent complex type RequestAbstractType from which all SAML request types are derived
        RequestAbstractType requestMessage = null;
        if (!isLogout) {
            requestMessage = buildAuthnRequest(request);
            /*if (getSSOAgentConfig().getSAML2().isRequestSigned()) {
                //  TODO: signing the AuthnRequest - setSignature method in SSOAgentUtils, X509 Credentials considered
            }*/
        } else {
            //  TODO: logout test
        }

        String encodedRequestMessage = SSOAgentUtils.
                encodeRequestMessage(requestMessage, SAMLConstants.SAML2_POST_BINDING_URI);

        Map<String, String[]> parameters = new HashMap<>();
        parameters.
                put(SSOAgentConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_REQUEST, new String[] { encodedRequestMessage });
        if (Optional.ofNullable(getSSOAgentConfig().getSAML2().getRelayState()).isPresent()) {
            parameters.put(RelayState.DEFAULT_ELEMENT_LOCAL_NAME,
                    new String[] { getSSOAgentConfig().getSAML2().getRelayState() });
        }

        //  Add any additional parameters defined
        if ((Optional.ofNullable(getSSOAgentConfig().getQueryParameters()).isPresent()) && (!getSSOAgentConfig().
                getQueryParameters().isEmpty())) {
            parameters.putAll(getSSOAgentConfig().getQueryParameters());
        }

        StringBuilder htmlParameters = new StringBuilder();
        parameters.entrySet().stream().forEach(entry -> {
            if ((Optional.ofNullable(entry.getKey()).isPresent()) && (Optional.ofNullable(entry.getValue()).isPresent())
                    && (entry.getValue().length > 0)) {
                Stream.of(entry.getValue()).forEach(
                        parameter -> htmlParameters.append("<input type='hidden' name='").append(entry.getKey()).
                                append("' value='").append(parameter).append("'>\n"));
            }
        });

        String htmlPayload = getSSOAgentConfig().getSAML2().getPostBindingRequestHTMLPayload();
        if ((!Optional.ofNullable(htmlPayload).isPresent()) || (!htmlPayload.contains("<!--$saml_params-->"))) {
            htmlPayload = "<html>\n" +
                    "<body>\n" +
                    "<p>You are now redirected back to " + getSSOAgentConfig().getSAML2().getIdPURL() + " \n" +
                    "If the redirection fails, please click the post button.</p>\n" +
                    "<form method='post' action='" + getSSOAgentConfig().getSAML2().getIdPURL() + "'>\n" +
                    "<p>\n" +
                    htmlParameters.toString() +
                    "<button type='submit'>POST</button>\n" +
                    "</p>\n" +
                    "</form>\n" +
                    "<script type='text/javascript'>\n" +
                    "document.forms[0].submit();\n" +
                    "</script>\n" +
                    "</body>\n" +
                    "</html>";
        } else {
            htmlPayload = htmlPayload.replace("<!--$saml_params-->", htmlParameters.toString());
        }
        return htmlPayload;
    }

    /**
     * Processes a SAML 2.0 response depending on its type, either a SAML 2.0 Response for a single-sign-on SAML
     * 2.0 Request by the client application or a SAML 2.0 Response for a single-logout SAML 2.0 Request from a
     * service provider.
     *
     * @param request the servlet request processed
     * @throws SSOException if SAML 2.0 response is null
     */
    public void processResponse(HttpServletRequest request) throws SSOException {
        String saml2SSOResponse = request.getParameter(SSOAgentConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_RESPONSE);

        if (Optional.ofNullable(saml2SSOResponse).isPresent()) {
            String decodedResponse = new String(Base64.decode(saml2SSOResponse), Charset.forName("UTF-8"));
            XMLObject samlObject = SSOAgentUtils.unmarshall(decodedResponse);
            if (samlObject instanceof LogoutResponse) {
                //  This is a SAML response for a single logout request from the service provider
//                performSingleLogout(request);
            } else {
                processSSOResponse(request);
            }
            String relayState = request.getParameter(RelayState.DEFAULT_ELEMENT_LOCAL_NAME);

            if ((Optional.ofNullable(relayState).isPresent()) && !relayState.isEmpty() && !"null"
                    .equalsIgnoreCase(relayState)) {
                //  Additional checks for incompetent IdPs
                getSSOAgentConfig().getSAML2().setRelayState(relayState);
            }

        } else {
            throw new SSOException("Invalid SAML2 Response. SAML2 Response can not be null.");
        }
    }

    //  TODO: add java doc comments
    private void processSSOResponse(HttpServletRequest request) throws SSOException {

    }

    /**
     * Returns a SAML 2.0 Authentication Request (AuthnRequest) instance based on the HTTP servlet request.
     *
     * @param request the HTTP servlet request used to build up the Authentication Request
     * @return a SAML 2.0 Authentication Request (AuthnRequest) instance
     */
    private AuthnRequest buildAuthnRequest(HttpServletRequest request) {
        //  Issuer identifies the entity that generated the request message
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(getSSOAgentConfig().getSAML2().getSPEntityId());

        //  NameIDPolicy element tailors the subject name identifier of assertions resulting from AuthnRequest
        NameIDPolicy nameIdPolicy = new NameIDPolicyBuilder().buildObject();
        //  URI reference corresponding to a name identifier format
        nameIdPolicy.setFormat(SSOAgentConstants.SAML2SSO.AUTH_REQUEST_NAME_ID_POLICY_FORMAT);
        //  Unique identifier of the service provider or affiliation of providers for whom the identifier was generated
        nameIdPolicy.setSPNameQualifier(SSOAgentConstants.SAML2SSO.AUTH_REQUEST_SERVICE_PROVIDER_NAME_QUALIFIER);
        //  Identity provider is allowed, in the course of fulfilling the request to generate a new identifier to
        //  represent the principal
        nameIdPolicy.setAllowCreate(true);

        //  This represents a URI reference identifying an authentication context class that describes the
        //  authentication context declaration that follows
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setAuthnContextClassRef(SSOAgentConstants.SAML2SSO.AUTH_CONTEXT_CLASS_URI_REFERENCE);

        //  Specifies the authentication context requirements of authentication statements returned in response
        //  to a request or query
        RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
        //  Resulting authentication context in the authentication statement must be the exact match of the
        //  authentication context specified
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        DateTime issueInstant = new DateTime();

        //  Create an AuthnRequest instance
        AuthnRequest authRequest = new AuthnRequestBuilder().buildObject();

        authRequest.setForceAuthn(getSSOAgentConfig().getSAML2().isForceAuthn());
        authRequest.setIsPassive(getSSOAgentConfig().getSAML2().isPassiveAuthn());
        authRequest.setIssueInstant(issueInstant);
        authRequest.setProtocolBinding(getSSOAgentConfig().getSAML2().getHttpBinding());
        authRequest.setAssertionConsumerServiceURL(getSSOAgentConfig().getSAML2().getACSURL());
        authRequest.setIssuer(issuer);
        authRequest.setNameIDPolicy(nameIdPolicy);
        authRequest.setRequestedAuthnContext(requestedAuthnContext);
        authRequest.setID(SSOAgentUtils.createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(getSSOAgentConfig().getSAML2().getIdPURL());

        //  If any optional protocol message extension elements that are agreed on between the communicating parties
        if (Optional.ofNullable(request.getAttribute(Extensions.LOCAL_NAME)).isPresent()) {
            authRequest.setExtensions((Extensions) request.getAttribute(Extensions.LOCAL_NAME));
        }

        //  Requesting SAML Attributes which the requester desires to be supplied by the identity provider.
        //  This Index value is registered in the identity provider
        String index = getSSOAgentConfig().getSAML2().getAttributeConsumingServiceIndex();
        if ((Optional.ofNullable(index).isPresent()) && !(index.trim().isEmpty())) {
            authRequest.setAttributeConsumingServiceIndex(Integer.parseInt(index));
        }

        return authRequest;
    }

    /**
     * Loads a custom signature validator class specified in the SSO Agent configurations.
     */
    /*private void loadCustomSignatureValidatorClass() {
        //  Load custom Signature Validator Class
        Optional.ofNullable(getSSOAgentConfig()).ifPresent(
                agent -> Optional.ofNullable(agent.getSAML2().getSignatureValidatorImplClass()).ifPresent(implClass -> {
                    try {
                        SSOAgentDataHolder.getInstance().
                                setSignatureValidator(Class.forName(implClass).newInstance());
                    } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                        logger.log(Level.SEVERE, "Error loading custom signature validator class", e);
                    }
                }));
    }*/
}
