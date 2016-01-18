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

import org.apache.catalina.connector.Request;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;
import org.wso2.appserver.webapp.security.sso.SSOConstants;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.wso2.appserver.webapp.security.sso.util.SSOAgentDataHolder;
import org.wso2.appserver.webapp.security.sso.agent.SSOAgentSessionManager;
import org.wso2.appserver.webapp.security.sso.bean.LoggedInSessionBean;
import org.wso2.appserver.webapp.security.sso.agent.SSOAgentConfiguration;
import org.wso2.appserver.webapp.security.sso.SSOUtils;
import org.wso2.appserver.webapp.security.sso.util.SignatureValidator;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * This class manages the generation of varied request and response types that are utilized
 * within the SAML 2.0 single-sign-on (SSO) process.
 *
 * @since 6.0.0
 */
public class SAML2SSOManager {
    private static final Logger logger = Logger.getLogger(SSOUtils.class.getName());

    private SSOAgentConfiguration ssoAgentConfiguration;

    public SAML2SSOManager(SSOAgentConfiguration ssoAgentConfiguration) throws SSOException {
        setSSOAgentConfig(ssoAgentConfiguration);
        loadCustomSignatureValidatorClass();
        SAMLSSOUtils.doBootstrap();
    }

    public static Logger getLogger() {
        return logger;
    }

    private void setSSOAgentConfig(SSOAgentConfiguration ssoAgentConfiguration) {
        this.ssoAgentConfiguration = ssoAgentConfiguration;
    }

    public SSOAgentConfiguration getSSOAgentConfig() {
        return ssoAgentConfiguration;
    }

    /**
     * Loads a custom signature validator class specified in the SSO Agent configurations.
     */
    private void loadCustomSignatureValidatorClass() {
        //  Load custom Signature Validator Class
        Optional.ofNullable(getSSOAgentConfig()).ifPresent(
                agent -> Optional.ofNullable(agent.getSAML2().getSignatureValidatorImplClass()).ifPresent(implClass -> {
                    try {
                        SSOAgentDataHolder.getInstance().
                                setObject(Class.forName(implClass).newInstance());
                    } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                        logger.log(Level.SEVERE, "Error loading custom signature validator class.", e);
                    }
                }));
    }

    /**
     * Handles the request for HTTP POST binding.
     *
     * @param request  the HTTP servlet request with SAML 2.0 message
     * @param isLogout true if request is a logout request, else false
     * @return the HTML payload to be transmitted
     * @throws SSOException if SSO session is null
     */
    protected String buildPostRequest(HttpServletRequest request, boolean isLogout) throws SSOException {
        //  Parent complex type RequestAbstractType from which all SAML request types are derived
        RequestAbstractType requestMessage;
        if (!isLogout) {
            requestMessage = buildAuthnRequest(request);
            if (getSSOAgentConfig().getSAML2().isRequestSigned()) {
                requestMessage = SAMLSSOUtils.
                        setSignature((AuthnRequest) requestMessage, XMLSignature.ALGO_ID_SIGNATURE_RSA,
                                new X509CredentialImplementation(
                                        getSSOAgentConfig().getSAML2().getSSOAgentX509Credential()));
            }
        } else {
            LoggedInSessionBean sessionBean = (LoggedInSessionBean) request.getSession(false).
                    getAttribute(SSOConstants.SESSION_BEAN_NAME);
            if (Optional.ofNullable(sessionBean).isPresent()) {
                requestMessage = buildLogoutRequest(sessionBean.getSAML2SSO().getSubjectId(),
                        sessionBean.getSAML2SSO().getSessionIndex());
                if (getSSOAgentConfig().getSAML2().isRequestSigned()) {
                    requestMessage = SAMLSSOUtils.
                            setSignature((LogoutRequest) requestMessage, XMLSignature.ALGO_ID_SIGNATURE_RSA,
                                    new X509CredentialImplementation(
                                            getSSOAgentConfig().getSAML2().getSSOAgentX509Credential()));
                }
            } else {
                throw new SSOException(
                        "Single-logout (SLO) Request cannot be built. Single-sign-on (SSO) Session is null.");
            }
        }

        String encodedRequestMessage = SAMLSSOUtils.
                encodeRequestMessage(requestMessage, SAMLConstants.SAML2_POST_BINDING_URI);

        Map<String, String[]> parameters = new HashMap<>();
        parameters.
                put(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_REQUEST, new String[] { encodedRequestMessage });
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
        parameters.entrySet().stream().
                filter(entry -> ((Optional.ofNullable(entry.getKey()).isPresent()) &&
                        (Optional.ofNullable(entry.getValue()).isPresent()) && (entry.getValue().length > 0))).
                forEach(filteredEntry -> Stream.of(filteredEntry.getValue()).
                        forEach(parameter -> htmlParameters.append("<input type='hidden' name='").
                                append(filteredEntry.getKey()).append("' value='").append(parameter).append("'>\n")));

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
        nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        //  Unique identifier of the service provider or affiliation of providers for whom the identifier was generated
        nameIdPolicy.setSPNameQualifier("Issuer");
        //  Identity provider is allowed, in the course of fulfilling the request to generate a new identifier to
        //  represent the principal
        nameIdPolicy.setAllowCreate(true);

        //  This represents a URI reference identifying an authentication context class that describes the
        //  authentication context declaration that follows
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.
                setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

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
        authRequest.setID(SSOUtils.createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(getSSOAgentConfig().getSAML2().getIdPURL());

        //  If any optional protocol message extension elements that are agreed on between the communicating parties
        if (Optional.ofNullable(request.getAttribute(Extensions.LOCAL_NAME)).isPresent()) {
            authRequest.setExtensions((Extensions) request.getAttribute(Extensions.LOCAL_NAME));
        }

        //  Requesting SAML Attributes which the requester desires to be supplied by the identity provider,
        //  this Index value is registered in the identity provider
        String index = getSSOAgentConfig().getSAML2().getAttributeConsumingServiceIndex();
        if ((Optional.ofNullable(index).isPresent()) && !(index.trim().isEmpty())) {
            authRequest.setAttributeConsumingServiceIndex(Integer.parseInt(index));
        }

        return authRequest;
    }

    /**
     * Sends character data specified by the {@code htmlPayload} in the servlet response body.
     *
     * @param response    the servlet response body in which character data are to be sent
     * @param htmlPayload the character data to be sent in the servlet body
     * @throws SSOException if an error occurs while writing character data to the servlet
     *                      response body
     */
    protected void sendCharacterData(HttpServletResponse response, String htmlPayload) throws SSOException {
        try {
            Writer writer = response.getWriter();
            writer.write(htmlPayload);
            response.flushBuffer();
            //  Not closing the Writer instance, as its creator is the HttpServletResponse
        } catch (IOException e) {
            throw new SSOException("Error occurred while writing to HttpServletResponse.", e);
        }
    }

    /**
     * Returns the redirect path after single-logout (SLO), read from the {@code request}.
     * </p>
     * If the redirect path is read from session then it is removed. Priority order of reading the redirect path is from
     * the Session, Context and Config, respectively.
     *
     * @param request              the HTTP servlet request
     * @param redirectPathAfterSLO the redirect path specified under redirectPathAfterSLO property of global
     *                             single-sign-on (SSO) configurations
     * @return redirect path relative to the current application path
     */
    protected String readAndForgetRedirectPathAfterSLO(Request request, String redirectPathAfterSLO) {
        Optional<String> redirectPath = Optional.empty();

        if (Optional.ofNullable(request.getSession(false)).isPresent()) {
            redirectPath = Optional.ofNullable((String) request.getSession(false).
                    getAttribute(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO));
            request.getSession(false).removeAttribute(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO);
        }

        if (!redirectPath.isPresent()) {
            redirectPath = Optional.ofNullable(
                    request.getContext().findParameter(SSOConstants.SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO));
        }

        if (!redirectPath.isPresent()) {
            redirectPath = Optional.ofNullable(redirectPathAfterSLO);
        }

        if ((redirectPath.isPresent()) && (!redirectPath.get().isEmpty())) {
            redirectPath = Optional.ofNullable(request.getContext().getPath().concat(redirectPath.get()));
        } else {
            redirectPath = Optional.ofNullable(request.getContext().getPath());
        }

        getLogger().log(Level.FINE, "Redirect path = " + redirectPath);

        return redirectPath.get();
    }

    /**
     * Processes a SAML 2.0 response depending on its type, either a SAML 2.0 Response for a single-sign-on (SSO) SAML
     * 2.0 Request by the client application or a SAML 2.0 Response for a single-logout (SLO) SAML 2.0 Request from a
     * service provider.
     *
     * @param request the servlet request processed
     * @throws SSOException if SAML 2.0 response is null
     */
    protected void processResponse(HttpServletRequest request) throws SSOException {
        String saml2SSOResponse = request.getParameter(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_RESPONSE);

        if (Optional.ofNullable(saml2SSOResponse).isPresent()) {
            String decodedResponse = new String(Base64.decode(saml2SSOResponse), Charset.forName("UTF-8"));
            XMLObject samlObject = SAMLSSOUtils.unmarshall(decodedResponse);
            if (samlObject instanceof LogoutResponse) {
                //  This is a SAML response for a single logout request from the service provider
                performSingleLogout(request);
            } else {
                processSingleSignInResponse(request);
            }
            String relayState = request.getParameter(RelayState.DEFAULT_ELEMENT_LOCAL_NAME);

            if ((Optional.ofNullable(relayState).isPresent()) && (!relayState.isEmpty()) && (!("null").
                    equalsIgnoreCase(relayState))) {
                //  Additional checks for incompetent IdPs
                getSSOAgentConfig().getSAML2().setRelayState(relayState);
            }
        } else {
            throw new SSOException("Invalid SAML2 Response. SAML2 Response cannot be null.");
        }
    }

    /**
     * Processes a single-sign-in SAML 2.0 Response received for an Authentication Request sent.
     *
     * @param request the HTTP servlet request used to process the SAML 2.0 Response
     * @throws SSOException if the received SAML 2.0 Response is invalid
     */
    private void processSingleSignInResponse(HttpServletRequest request) throws SSOException {
        LoggedInSessionBean sessionBean = new LoggedInSessionBean();
        sessionBean.setSAML2SSO(new LoggedInSessionBean.SAML2SSO());

        String saml2ResponseString = new String(
                Base64.decode(request.getParameter(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_RESPONSE)),
                Charset.forName("UTF-8"));
        Response saml2Response = (Response) SAMLSSOUtils.unmarshall(saml2ResponseString);
        sessionBean.getSAML2SSO().setResponseString(saml2ResponseString);
        sessionBean.getSAML2SSO().setSAMLResponse(saml2Response);

        Optional<Assertion> assertion = Optional.empty();
        if (getSSOAgentConfig().getSAML2().isAssertionEncrypted()) {
            List<EncryptedAssertion> encryptedAssertions = saml2Response.getEncryptedAssertions();
            EncryptedAssertion encryptedAssertion;
            if (!SSOUtils.isCollectionEmpty(encryptedAssertions)) {
                encryptedAssertion = encryptedAssertions.stream().findFirst().get();
                try {
                    assertion = Optional.ofNullable(
                            SAMLSSOUtils.decryptAssertion(getSSOAgentConfig().getSAML2().getSSOAgentX509Credential(),
                                    encryptedAssertion));
                } catch (Exception e) {
                    getLogger().log(Level.FINE, "Assertion decryption failure : ", e);
                    throw new SSOException("Unable to decrypt the SAML2 Assertion.");
                }
            }
        } else {
            List<Assertion> assertions = saml2Response.getAssertions();
            if (!SSOUtils.isCollectionEmpty(assertions)) {
                assertion = assertions.stream().findFirst();
            }
        }
        if (!assertion.isPresent()) {
            if (isNoPassive(saml2Response)) {
                getLogger().log(Level.FINE, "Cannot authenticate in passive mode.");
                return;
            }
            throw new SSOException("SAML2 Assertion not found in the Response.");
        }

        Optional<String> idPEntityIdValue = Optional.ofNullable(assertion.get().getIssuer().getValue());
        if ((!idPEntityIdValue.isPresent()) || (idPEntityIdValue.get().isEmpty())) {
            throw new SSOException("SAML2 Response does not contain an Issuer value.");
        } else if (!idPEntityIdValue.get().equals(getSSOAgentConfig().getSAML2().getIdPEntityId())) {
            throw new SSOException("SAML2 Response Issuer verification failed.");
        }
        sessionBean.getSAML2SSO().setAssertion(assertion.get());
        //  Cannot marshall SAML assertion here, before signature validation due to an issue in OpenSAML

        //  Gets the subject name from the Response Object and forward it to login_action.jsp
        Optional<String> subject = Optional.empty();
        if ((Optional.ofNullable(assertion.get().getSubject()).isPresent()) &&
                (Optional.ofNullable(assertion.get().getSubject().getNameID()).isPresent())) {
            subject = Optional.of(assertion.get().getSubject().getNameID().getValue());
        }
        if (!subject.isPresent()) {
            throw new SSOException("SAML2 Response does not contain the name of the subject.");
        }

        //  Sets the subject in the session bean
        sessionBean.getSAML2SSO().setSubjectId(subject.get());
        request.getSession().setAttribute(SSOConstants.SESSION_BEAN_NAME, sessionBean);

        //  Validates the audience restriction
        validateAudienceRestriction(assertion.get());

        //  Validate signature
        //  TODO: changed
        validateSignature(saml2Response, assertion.get());

        //  Marshalling SAML2 assertion after signature validation due to a weird issue in OpenSAML
        sessionBean.getSAML2SSO().setAssertionString(SAMLSSOUtils.marshall(assertion.get()));

        ((LoggedInSessionBean) request.getSession().getAttribute(SSOConstants.SESSION_BEAN_NAME)).getSAML2SSO().
                setSubjectAttributes(getAssertionStatements(assertion.get()));

        //  For removing the session when the single-logout request made by the service provider itself
        if (getSSOAgentConfig().getSAML2().isSLOEnabled()) {
            Optional<String> sessionId = Optional.
                    ofNullable(assertion.get().getAuthnStatements().stream().findFirst().get().getSessionIndex());
            if (!sessionId.isPresent()) {
                throw new SSOException("Single Logout is enabled but IdP Session ID not found in SAML2 Assertion");
            }
            ((LoggedInSessionBean) request.getSession().
                    getAttribute(SSOConstants.SESSION_BEAN_NAME)).getSAML2SSO().setSessionIndex(sessionId.get());
            SSOAgentSessionManager.addAuthenticatedSession(request.getSession(false));
        }

        request.getSession().setAttribute(SSOConstants.SESSION_BEAN_NAME, sessionBean);
    }

    /**
     * Returns true if the identity provider cannot authenticate the principal passively, as requested, else false.
     *
     * @param response the SAML 2.0 Response to be evaluated
     * @return true if the identity provider cannot authenticate the principal passively, as requested, else false
     */
    private boolean isNoPassive(Response response) {
        return (Optional.ofNullable(response.getStatus()).isPresent()) &&
                (Optional.ofNullable(response.getStatus().getStatusCode()).isPresent()) &&
                (response.getStatus().getStatusCode().getValue().equals(StatusCode.RESPONDER_URI)) &&
                (Optional.ofNullable(response.getStatus().getStatusCode().getStatusCode()).isPresent()) &&
                (response.getStatus().getStatusCode().getStatusCode().getValue().equals(StatusCode.NO_PASSIVE_URI));
    }

    /**
     * Validates the SAML 2.0 Audience Restrictions set in the specified SAML 2.0 Assertion.
     *
     * @param assertion the SAML 2.0 Assertion in which Audience Restrictions' validity is checked for
     * @throws SSOException if the Audience Restriction validation fails
     */
    private void validateAudienceRestriction(Assertion assertion) throws SSOException {
        if (!Optional.ofNullable(assertion).isPresent()) {
            return;
        }

        Conditions conditions = assertion.getConditions();
        if (!Optional.ofNullable(conditions).isPresent()) {
            throw new SSOException("SAML2 Response doesn't contain Conditions.");
        }

        List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
        if ((!Optional.ofNullable(audienceRestrictions).isPresent()) || (audienceRestrictions.isEmpty())) {
            throw new SSOException("SAML2 Response doesn't contain AudienceRestrictions.");
        }

        Stream<AudienceRestriction> audienceExistingStream = audienceRestrictions.stream().filter(audienceRestriction ->
                (((Optional.ofNullable(audienceRestriction.getAudiences()).isPresent()) && (!audienceRestriction.
                        getAudiences().isEmpty()))) && (audienceRestriction.getAudiences().stream().
                        filter(audience -> getSSOAgentConfig().getSAML2().getSPEntityId().
                                equals(audience.getAudienceURI()))).count() > 0);

        if (audienceExistingStream.count() == 0) {
            throw new SSOException("SAML2 Assertion Audience Restriction validation failed.");
        }
    }

    private void validateSignature(Response response, Assertion assertion) throws SSOException {
        if (Optional.ofNullable(SSOAgentDataHolder.getInstance().getObject()).isPresent()) {
            //  Custom implementation of signature validation
            SignatureValidator signatureValidatorUtility = (SignatureValidator) SSOAgentDataHolder.
                    getInstance().getObject();
            signatureValidatorUtility.validateSignature(response, assertion, getSSOAgentConfig());
        } else {
            //  If custom implementation not found, execute the default implementation
            if (getSSOAgentConfig().getSAML2().isResponseSigned()) {
                if (!Optional.ofNullable(response.getSignature()).isPresent()) {
                    throw new SSOException("SAML2 Response signing is enabled, but signature element not " +
                            "found in SAML2 Response element.");
                } else {
                    try {
                        org.opensaml.xml.signature.SignatureValidator validator = new org.opensaml.xml.signature.SignatureValidator(new X509CredentialImplementation(
                                getSSOAgentConfig().getSAML2().getSSOAgentX509Credential()));
                        validator.validate(response.getSignature());
                    } catch (ValidationException e) {
                        getLogger().log(Level.FINE, "Validation exception : ", e);
                        throw new SSOException("Signature validation failed for SAML2 Response.");
                    }
                }
            }
            if (getSSOAgentConfig().getSAML2().isAssertionSigned()) {
                if (!Optional.ofNullable(assertion.getSignature()).isPresent()) {
                    throw new SSOException("SAML2 Assertion signing is enabled, but signature element not " +
                            "found in SAML2 Assertion element.");
                } else {
                    try {
                        org.opensaml.xml.signature.SignatureValidator validator = new org.opensaml.xml.signature.SignatureValidator(new X509CredentialImplementation(
                                getSSOAgentConfig().getSAML2().getSSOAgentX509Credential()));
                        validator.validate(assertion.getSignature());
                    } catch (ValidationException e) {
                        getLogger().log(Level.FINE, "Validation exception : ", e);
                        throw new SSOException("Signature validation failed for SAML2 Assertion.");
                    }
                }
            }
        }
    }






    //  TODO: WRITE JAVADOCS AND TEST
    public String buildRedirectRequest(HttpServletRequest request, boolean isLogout) throws SSOException {
        RequestAbstractType requestMessage;
        if (!isLogout) {
            requestMessage = buildAuthnRequest(request);
        } else {
            LoggedInSessionBean sessionBean = (LoggedInSessionBean) request.getSession(false).
                    getAttribute(SSOConstants.SESSION_BEAN_NAME);
            if (Optional.ofNullable(sessionBean).isPresent()) {
                requestMessage = buildLogoutRequest(sessionBean.getSAML2SSO().getSubjectId(),
                        sessionBean.getSAML2SSO().getSessionIndex());
            } else {
                throw new SSOException("SLO Request can not be built. SSO Session is null.");
            }
        }

        String idpUrl;
        String encodedRequestMessage = SAMLSSOUtils.
                encodeRequestMessage(requestMessage, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        StringBuilder httpQueryString = new StringBuilder(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_REQUEST +
                "=" + encodedRequestMessage);

        String relayState = getSSOAgentConfig().getSAML2().getRelayState();
        if (Optional.ofNullable(relayState).isPresent()) {
            try {
                httpQueryString.append("&").append(RelayState.DEFAULT_ELEMENT_LOCAL_NAME).append("=").
                        append(URLEncoder.encode(relayState, "UTF-8").trim());
            } catch (UnsupportedEncodingException e) {
                throw new SSOException("Error occurred while URLEncoding " + RelayState.DEFAULT_ELEMENT_LOCAL_NAME, e);
            }
        }

        //  Add any additional parameters defined
        if ((Optional.ofNullable(getSSOAgentConfig().getQueryParameters()).isPresent()) && (!getSSOAgentConfig().
                getQueryParameters().isEmpty())) {
            StringBuilder builder = new StringBuilder();
            getSSOAgentConfig().getQueryParameters().entrySet().stream().filter(entry ->
                    ((Optional.ofNullable(entry.getKey()).isPresent()) && (Optional.ofNullable(entry.getValue()).
                            isPresent()) && (entry.getValue().length > 0))).
                    forEach(filteredEntry -> Stream.of(filteredEntry.getValue()).forEach(
                            parameter -> builder.append("&").append(filteredEntry.getKey()).
                                    append("=").append(parameter)));
            httpQueryString.append(builder);
        }

        //  TODO: CONSIDER DIGITAL SIGNING

        if (getSSOAgentConfig().getSAML2().getIdPURL().contains("?")) {
            idpUrl = getSSOAgentConfig().getSAML2().getIdPURL().concat("&").concat(httpQueryString.toString());
        } else {
            idpUrl = getSSOAgentConfig().getSAML2().getIdPURL().concat("?").concat(httpQueryString.toString());
        }
        return idpUrl;
    }

    /**
     * Performs single-logout (SLO) function based on the HTTP servlet request.
     *
     * @param request the HTTP servlet request
     * @throws SSOException if the SAML 2.0 Single Logout Request/Response is invalid
     */
    public void performSingleLogout(HttpServletRequest request) throws SSOException {
        Optional<XMLObject> saml2Object = Optional.empty();

        if (Optional.ofNullable(request.getParameter(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_REQUEST)).
                isPresent()) {
            saml2Object = Optional.ofNullable(SAMLSSOUtils.unmarshall(
                    new String(Base64.decode(request.getParameter(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_REQUEST)),
                            Charset.forName("UTF-8"))));
        }
        if (!saml2Object.isPresent()) {
            saml2Object = Optional.ofNullable(SAMLSSOUtils.unmarshall(new String(
                    Base64.decode(request.getParameter(SSOConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_RESPONSE)),
                    Charset.forName("UTF-8"))));
        }
        if (saml2Object.get() instanceof LogoutRequest) {
            LogoutRequest logoutRequest = (LogoutRequest) saml2Object.get();
            logoutRequest.getSessionIndexes().stream().findFirst().ifPresent(
                    sessionIndex -> SSOAgentSessionManager.invalidateAllSessions(sessionIndex.getSessionIndex()).
                            stream().forEach(HttpSession::invalidate));
        } else if (saml2Object.get() instanceof LogoutResponse) {
            Optional.ofNullable(request.getSession(false)).ifPresent(session -> {
                //  Not invalidating session explicitly since there may be other listeners
                //  still waiting to get triggered and at the end of the chain session needs to be
                //  invalidated by the system.
                Set<HttpSession> sessions = SSOAgentSessionManager.invalidateAllSessions(request.getSession(false));
                sessions.stream().forEach(httpSession -> {
                    try {
                        httpSession.invalidate();
                    } catch (IllegalStateException ignore) {
                        getLogger().log(Level.FINE, "Ignoring exception : ", ignore);
                    }
                });
            });
        } else {
            throw new SSOException("Invalid SAML2 Single Logout Request/Response.");
        }
    }

    /**
     * Returns a SAML 2.0 Logout Request (LogoutRequest) instance.
     *
     * @param user         the identifier that specify the principal as currently recognized by the identity and
     *                     service providers
     * @param sessionIndex the identifier that indexes this session at the message recipient
     * @return a SAML 2.0 Logout Request (LogoutRequest) instance
     */
    private LogoutRequest buildLogoutRequest(String user, String sessionIndex) {
        //  Creates a Logout Request instance
        LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject();

        logoutRequest.setID(SSOUtils.createID());
        logoutRequest.setDestination(getSSOAgentConfig().getSAML2().getIdPURL());

        DateTime issueInstant = new DateTime();
        logoutRequest.setIssueInstant(issueInstant);
        //  Time at which the request expires, after which the recipient may discard the message
        logoutRequest.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + (5 * 60 * 1000)));

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(getSSOAgentConfig().getSAML2().getSPEntityId());
        logoutRequest.setIssuer(issuer);

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        nameId.setValue(user);
        logoutRequest.setNameID(nameId);

        SessionIndex sessionIndexElement = new SessionIndexBuilder().buildObject();
        sessionIndexElement.setSessionIndex(sessionIndex);
        logoutRequest.getSessionIndexes().add(sessionIndexElement);

        //  Indicates the reason for the logout
        logoutRequest.setReason("Single Logout");

        return logoutRequest;
    }

    /**
     * Returns SAML 2.0 Assertion Attribute Statement content.
     *
     * @param assertion the SAML 2.0 Assertion whose content is to be returned
     * @return Attribute Statement content of the SAML 2.0 Assertion specified
     */
    private Map<String, String> getAssertionStatements(Assertion assertion) {
        Map<String, String> results = new HashMap<>();
        if ((Optional.ofNullable(assertion).isPresent()) &&
                (Optional.ofNullable(assertion.getAttributeStatements()).isPresent())) {
            Stream<AttributeStatement> attributeStatements = assertion.getAttributeStatements().stream();
            attributeStatements.forEach(attributeStatement ->
                    attributeStatement.getAttributes().stream().forEach(attribute -> {
                        Element value = attribute.getAttributeValues().get(0).getDOM();
                        String attributeValue = value.getTextContent();
                        results.put(attribute.getName(), attributeValue);
                    }));
        }
        return results;
    }
}
