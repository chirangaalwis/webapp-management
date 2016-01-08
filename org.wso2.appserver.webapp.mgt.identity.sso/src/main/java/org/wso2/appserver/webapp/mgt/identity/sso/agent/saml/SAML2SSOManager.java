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
            List<Assertion> assertions = saml2Response.getAssertions();
            if ((Optional.ofNullable(assertions).isPresent()) && (!assertions.isEmpty())) {
                assertion = Optional.of(assertions.get(0));
            }
        }
        if (!Optional.ofNullable(assertion).isPresent()) {
            if (isNoPassive(saml2Response)) {
                getLogger().log(Level.FINE, "Cannot authenticate in passive mode.");
                return;
            }
            throw new SSOException("SAML2 Assertion not found in the Response.");
        }

        String idPEntityIdValue = assertion.get().getIssuer().getValue();
        if ((!Optional.ofNullable(idPEntityIdValue).isPresent()) || (idPEntityIdValue.isEmpty())) {
            throw new SSOException("SAML2 Response does not contain an Issuer value.");
        } else if (!idPEntityIdValue.equals(getSSOAgentConfig().getSAML2().getIdPEntityId())) {
            throw new SSOException("SAML2 Response Issuer verification failed.");
        }
        sessionBean.getSAML2SSO().setAssertion(assertion.get());
        //  Cannot marshall SAML assertion here, before signature validation due to an issue in OpenSAML

        //  Get the subject name from the Response Object and forward it to login_action.jsp
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

        // validate audience restriction
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

    //  TODO: add comments, to be refactored
    protected void validateAudienceRestriction(Assertion assertion) throws SSOException {
/*        if (Optional.ofNullable(assertion).isPresent()) {
            if (!Optional.ofNullable(assertion.getConditions()).isPresent()) {
                throw new SSOException("SAML2 Response doesn't contain Conditions.");
            } else {
                List<AudienceRestriction> audienceRestrictions = assertion.getConditions().getAudienceRestrictions();
                if ((!Optional.ofNullable(audienceRestrictions).isPresent()) || (audienceRestrictions.isEmpty())) {
                    throw new SSOException("SAML2 Response doesn't contain AudienceRestrictions.");
                } else {
                    audienceRestrictions.stream().forEach(audienceRestriction -> {

                    });
                }
            }
        }*/

        if (assertion != null) {
            Conditions conditions = assertion.getConditions();
            if (conditions != null) {
                List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
                if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                    boolean audienceFound = false;
                    for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                        if (audienceRestriction.getAudiences() != null && !audienceRestriction.getAudiences().
                                isEmpty()) {
                            for (Audience audience : audienceRestriction.getAudiences()) {
                                if (getSSOAgentConfig().getSAML2().getSPEntityId().equals(audience.getAudienceURI())) {
                                    audienceFound = true;
                                    break;
                                }
                            }
                        }
                        if (audienceFound) {
                            break;
                        }
                    }
                    if (!audienceFound) {
                        throw new SSOException("SAML2 Assertion Audience Restriction validation failed");
                    }
                } else {
                    throw new SSOException("SAML2 Response doesn't contain AudienceRestrictions");
                }
            } else {
                throw new SSOException("SAML2 Response doesn't contain Conditions");
            }
        }
    }

    /**
     * Returns a SAML 2.0 Authentication Request (AuthnRequest) instance based on the HTTP servlet request.
     *
     * @param request the HTTP servlet request used to build up the Authentication Request
     * @return a SAML 2.0 Authentication Request (AuthnRequest) instance
     */
    private AuthnRequest buildAuthnRequest(HttpServletRequest request) {
        //  Issuer identifies the entity that generated the request message
        /*Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(getSSOAgentConfig().getSAML2().getSPEntityId());*/

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer =
                issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                        "Issuer", "samlp");
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
//        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();

        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef =
                authnContextClassRefBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                        "AuthnContextClassRef",
                        "saml");
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
//        AuthnRequest authRequest = new AuthnRequestBuilder().buildObject();

        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest =
                authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                        "AuthnRequest", "samlp");

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

    private boolean isNoPassive(Response response) {
        return (Optional.ofNullable(response.getStatus()).isPresent()) &&
                (Optional.ofNullable(response.getStatus().getStatusCode()).isPresent()) &&
                (response.getStatus().getStatusCode().getValue().equals(StatusCode.RESPONDER_URI)) &&
                (Optional.ofNullable(response.getStatus().getStatusCode().getStatusCode()).isPresent()) &&
                (response.getStatus().getStatusCode().getStatusCode().getValue().equals(StatusCode.NO_PASSIVE_URI));
    }

    //  TODO: to be refactored
    private Map<String, String> getAssertionStatements(Assertion assertion) {

        Map<String, String> results = new HashMap<>();

        if (assertion != null && assertion.getAttributeStatements() != null) {

            List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    Element value = attribute.getAttributeValues().get(0).getDOM();
                    String attributeValue = value.getTextContent();
                    results.put(attribute.getName(), attributeValue);
                }
            }

        }
        return results;
    }

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
}
