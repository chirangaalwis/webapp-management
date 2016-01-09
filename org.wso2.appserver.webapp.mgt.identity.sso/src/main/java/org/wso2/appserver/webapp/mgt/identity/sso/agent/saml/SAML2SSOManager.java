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
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.appserver.webapp.mgt.identity.sso.SSOException;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.SSOAgentConstants;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.model.LoggedInSessionBean;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.model.SSOAgentConfiguration;
import org.wso2.appserver.webapp.mgt.identity.sso.agent.util.SSOAgentUtils;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;

/**
 * This class manages the generation of varied request and response types that are utilized
 * within the SAML 2.0 single-sign-on process.
 */
public class SAML2SSOManager {
    private static final Logger logger = Logger.getLogger(SSOAgentUtils.class.getName());

    private SSOAgentConfiguration ssoAgentConfiguration;

    public SAML2SSOManager(SSOAgentConfiguration ssoAgentConfiguration) throws SSOException {
        setSSOAgentConfig(ssoAgentConfiguration);
        //  TODO: uncomment later
//        loadCustomSignatureValidatorClass();
        SSOAgentUtils.doBootstrap();
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
     * Processes a SAML 2.0 response depending on its type, either a SAML 2.0 Response for a single-sign-on (SSO) SAML
     * 2.0 Request by the client application or a SAML 2.0 Response for a single-logout (SLO) SAML 2.0 Request from a
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

            if ((Optional.ofNullable(relayState).isPresent()) && !relayState.isEmpty() && !(("null").
                    equalsIgnoreCase(relayState))) {
                //  Additional checks for incompetent IdPs
                getSSOAgentConfig().getSAML2().setRelayState(relayState);
            }
        } else {
            throw new SSOException("Invalid SAML2 Response. SAML2 Response can not be null.");
        }
    }

    //  TODO: add java doc comments
    private void processSSOResponse(HttpServletRequest request) throws SSOException {
        LoggedInSessionBean sessionBean = new LoggedInSessionBean();
        sessionBean.setSAML2SSO(new LoggedInSessionBean.SAML2SSO());

        String saml2ResponseString = new String(
                Base64.decode(request.getParameter(SSOAgentConstants.SAML2SSO.HTTP_POST_PARAM_SAML2_RESPONSE)),
                Charset.forName("UTF-8"));
        Response saml2Response = (Response) SSOAgentUtils.unmarshall(saml2ResponseString);
        sessionBean.getSAML2SSO().setResponseString(saml2ResponseString);
        sessionBean.getSAML2SSO().setSAMLResponse(saml2Response);

        Optional<Assertion> assertion = Optional.empty();
        if (getSSOAgentConfig().getSAML2().isAssertionEncrypted()) {
            //  TODO: to be completed under assertion signing
        } else {
            Optional<List<Assertion>> assertions = Optional.ofNullable(saml2Response.getAssertions());
            if ((assertions.isPresent()) && (!assertions.get().isEmpty())) {
                assertion = assertions.get().stream().findFirst();
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
        if ((Optional.ofNullable(assertion.get().getSubject()).isPresent()) && (Optional.
                ofNullable(assertion.get().getSubject().getNameID()).isPresent())) {
            subject = Optional.of(assertion.get().getSubject().getNameID().getValue());
        }
        if (!subject.isPresent()) {
            throw new SSOException("SAML2 Response does not contain the name of the subject.");
        }

        //  Sets the subject in the session bean
        sessionBean.getSAML2SSO().setSubjectId(subject.get());
        request.getSession().setAttribute(SSOAgentConstants.SESSION_BEAN_NAME, sessionBean);

        // Validates the audience restriction
        validateAudienceRestriction(assertion.get());

        // validate signature
//        validateSignature(saml2Response, assertion);

        // Marshalling SAML2 assertion after signature validation due to a weird issue in OpenSAML
        sessionBean.getSAML2SSO().setAssertionString(marshall(assertion.get()));

        ((LoggedInSessionBean) request.getSession().getAttribute(
                SSOAgentConstants.SESSION_BEAN_NAME)).getSAML2SSO().
                setSubjectAttributes(getAssertionStatements(assertion.get()));

        //  TODO: Single log out code

        request.getSession().setAttribute(SSOAgentConstants.SESSION_BEAN_NAME, sessionBean);
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

        //  Requesting SAML Attributes which the requester desires to be supplied by the identity provider,
        //  this Index value is registered in the identity provider
        String index = getSSOAgentConfig().getSAML2().getAttributeConsumingServiceIndex();
        if ((Optional.ofNullable(index).isPresent()) && !(index.trim().isEmpty())) {
            authRequest.setAttributeConsumingServiceIndex(Integer.parseInt(index));
        }

        return authRequest;
    }

    //  TODO: REFACTORING, POSSIBILITY OF MOVING TO UTILS AND COMMENTS
    protected String marshall(XMLObject xmlObject) throws SSOException {

        try {
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");
            MarshallerFactory marshallerFactory =
                    org.opensaml.xml.Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);
            ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return new String(byteArrayOutputStrm.toByteArray(), Charset.forName("UTF-8"));
        } catch (ClassNotFoundException | InstantiationException | MarshallingException | IllegalAccessException e) {
            throw new SSOException("Error in marshalling SAML2 Assertion", e);
        }
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

    //  TODO: ADD JAVADOC COMMENTS
    private Map<String, String> getAssertionStatements(Assertion assertion) {
        Map<String, String> results = new HashMap<>();
        if ((Optional.ofNullable(assertion).isPresent()) && (Optional.ofNullable(assertion.getAttributeStatements()).
                isPresent())) {
            Stream<AttributeStatement> attributeStatements = assertion.getAttributeStatements().stream();
            attributeStatements.
                    forEach(attributeStatement -> attributeStatement.getAttributes().stream().forEach(attribute -> {
                        Element value = attribute.getAttributeValues().get(0).getDOM();
                        String attributeValue = value.getTextContent();
                        results.put(attribute.getName(), attributeValue);
                    }));
        }
        return results;
    }
}
