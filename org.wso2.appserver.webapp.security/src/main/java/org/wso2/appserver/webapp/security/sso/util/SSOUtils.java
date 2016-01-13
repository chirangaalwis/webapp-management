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

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.appserver.webapp.security.sso.SSOConstants;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * This class contains utility methods used for the implementation of the single-sign-on (SSO) functionality.
 *
 * @since 6.0.0
 */
public class SSOUtils {
    private static final Logger logger = Logger.getLogger(SSOUtils.class.getName());
    private static final Random random = new Random();

    private static boolean bootStrapped;

    //  a static field initialization block
    static {
        setBootStrapped(false);
    }

    public static Logger getLogger() {
        return logger;
    }

    private static Random getRandom() {
        return random;
    }

    private static boolean isBootStrapped() {
        return bootStrapped;
    }

    private static void setBootStrapped(boolean bootStrapped) {
        SSOUtils.bootStrapped = bootStrapped;
    }

    /**
     * Returns a {@code Path} instance representing the base of Apache Tomcat instances.
     *
     * @return a {@link Path} instance representing the base of Apache Tomcat instances
     * @throws SSOException if CATALINA_BASE environmental variable has not been set
     */
    public static Path getCatalinaBase() throws SSOException {
        String envVariableValue = System.getProperty(SSOConstants.SAMLSSOValveConstants.CATALINA_BASE);
        if (Optional.ofNullable(envVariableValue).isPresent()) {
            return Paths.get(envVariableValue);
        } else {
            throw new SSOException("CATALINA_BASE environmental variable has not been set.");
        }
    }

    /**
     * Returns a {@code Path} instance representing the Apache Tomcat configuration home CATALINA_BASE/conf.
     *
     * @return a {@link Path} instance representing the Apache Tomcat configuration home CATALINA_BASE/conf
     * @throws SSOException if CATALINA_BASE environmental variable has not been set
     */
    public static Path getTomcatConfigurationHome() throws SSOException {
        return Paths.
                get(getCatalinaBase().toString(), SSOConstants.SAMLSSOValveConstants.TOMCAT_CONFIGURATION_FOLDER_NAME);
    }

    /**
     * Generates a unique id for authentication requests.
     *
     * @return a unique id for authentication requests
     */
    public static String createID() {
        byte[] bytes = new byte[20]; // 160 bit
        getRandom().nextBytes(bytes);
        char[] characterMapping = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p' };

        char[] characters = new char[40];
        IntStream.range(0, bytes.length).forEach(index -> {
            int left = (bytes[index] >> 4) & 0x0f;
            int right = bytes[index] & 0x0f;
            characters[index * 2] = characterMapping[left];
            characters[index * 2 + 1] = characterMapping[right];
        });

        return String.valueOf(characters);
    }

    /**
     * Returns true if the specified {@code String} is blank, else false.
     *
     * @param stringValue the {@link String} to be checked whether it is blank
     * @return true if the specified {@link String} is blank, else false
     */
    public static boolean isBlank(String stringValue) {
        if ((!Optional.ofNullable(stringValue).isPresent()) || (stringValue.isEmpty())) {
            return true;
        }
        Stream<Character> characterStream = stringValue.chars().
                mapToObj(intCharacter -> (char) intCharacter).parallel().filter(Character::isWhitespace);
        return characterStream.count() == stringValue.length();
    }

    /**
     * Returns a unique id value for the SAML 2.0 service provider application based on its context path.
     * </p>
     * An {@code Optional String} id is returned based on the context path provided.
     *
     * @param contextPath the context path of the service provider application
     * @return a unique id value for the SAML 2.0 service provider application based on its context path
     */
    public static Optional generateIssuerID(String contextPath) {
        if (Optional.ofNullable(contextPath).isPresent()) {
            String issuerId = contextPath.replaceFirst("/webapps", "").replace("/", "_");
            if (issuerId.startsWith("_")) {
                issuerId = issuerId.substring(1);
            }
            return Optional.of(issuerId);
        } else {
            return Optional.empty();
        }
    }

    /**
     * Returns a SAML 2.0 Assertion Consumer URL based on service provider application context path.
     * </p>
     * An {@code Optional String} URL is returned based on the context path and configuration properties provided.
     *
     * @param contextPath           the context path of the service provider application
     * @param ssoSPConfigProperties the global single-sign-on configuration properties
     * @return a SAML 2.0 Assertion Consumer URL based on service provider application context path
     */
    public static Optional generateConsumerUrl(String contextPath, Properties ssoSPConfigProperties) {
        if ((Optional.ofNullable(contextPath).isPresent()) && (Optional.ofNullable(ssoSPConfigProperties).
                isPresent())) {
            return Optional.of(ssoSPConfigProperties.getProperty(SSOConstants.SAMLSSOValveConstants.APP_SERVER_URL)
                    + contextPath +
                    ssoSPConfigProperties.getProperty(SSOConstants.SAMLSSOValveConstants.CONSUMER_URL_POSTFIX));
        } else {
            return Optional.empty();
        }
    }

    /**
     * Sends character data specified by the {@code htmlPayload} in the servlet response body.
     *
     * @param response    the servlet response body in which character data are to be sent
     * @param htmlPayload the character data to be sent in the servlet body
     * @throws SSOException if an error occurs while writing character data to the servlet
     *                      response body
     */
    public static void sendCharacterData(HttpServletResponse response, String htmlPayload) throws SSOException {
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
     * Initializes the OpenSAML2 library, if it is not initialized yet.
     * </p>
     * Calls the bootstrap method of {@code DefaultBootstrap}.
     *
     * @throws SSOException if an error occurs when bootstrapping the OpenSAML2 library
     */
    public static void doBootstrap() throws SSOException {
        if (!isBootStrapped()) {
            try {
                DefaultBootstrap.bootstrap();
                setBootStrapped(true);
            } catch (ConfigurationException e) {
                throw new SSOException("Error in bootstrapping the OpenSAML2 library.", e);
            }
        }
    }

    /**
     * Encodes the SAML 2.0 based request XML object into its corresponding Base64 notation, based on the type of
     * SAML 2.0 binding.
     *
     * @param requestMessage the {@link RequestAbstractType} XML object to be encoded
     * @param binding        the SAML 2.0 binding type
     * @return encoded {@link String} corresponding to the request XML object
     * @throws SSOException if an error occurs while encoding SAML2 request
     */
    public static String encodeRequestMessage(RequestAbstractType requestMessage, String binding) throws SSOException {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM;
        try {
            //  Marshall this element, and its children, and root them in a newly created Document
            authDOM = marshaller.marshall(requestMessage);
        } catch (MarshallingException e) {
            throw new SSOException("Error occurred while encoding SAML2 request. Failed to marshall the SAML 2.0. " +
                    "Request element XMLObject to its corresponding W3C DOM element.", e);
        }

        StringWriter writer = new StringWriter();
        //  Writes the node out to the writer using the DOM
        XMLHelper.writeNode(authDOM, writer);

        if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding)) {
            //  Compress the message, Base 64 encode and URL encode
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try (DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream,
                    deflater)) {
                deflaterOutputStream.write(writer.toString().getBytes(Charset.forName("UTF-8")));
                String encodedRequestMessage = Base64.
                        encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
                return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();
            } catch (IOException e) {
                throw new SSOException("Error occurred while encoding SAML2 request.", e);
            }
        } else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding)) {
            return Base64.
                    encodeBytes(writer.toString().getBytes(Charset.forName("UTF-8")), Base64.DONT_BREAK_LINES);
        } else {
            getLogger().log(Level.FINE,
                    "Unsupported SAML2 HTTP Binding. Defaulting to " + SAMLConstants.SAML2_POST_BINDING_URI + ".");
            return Base64.
                    encodeBytes(writer.toString().getBytes(Charset.forName("UTF-8")), Base64.DONT_BREAK_LINES);
        }
    }

    /**
     * Serializes the specified SAML 2.0 based XML content representation to its corresponding actual XML syntax
     * representation.
     *
     * @param xmlObject the SAML 2.0 based XML content object
     * @return a {@link String} representation of the actual XML representation of the SAML 2.0 based XML content
     * representation
     * @throws SSOException if an error occurs during the marshalling process
     */
    public static String marshall(XMLObject xmlObject) throws SSOException {
        try {
            //  Explicitly sets the special XML parser library to be used, in the global variables
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");
            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS implementation = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = implementation.createLSSerializer();
            LSOutput output = implementation.createLSOutput();
            output.setByteStream(byteArrayOutputStream);
            writer.write(element, output);
            return new String(byteArrayOutputStream.toByteArray(), Charset.forName("UTF-8"));
        } catch (ClassNotFoundException | InstantiationException | MarshallingException | IllegalAccessException e) {
            throw new SSOException("Error in marshalling SAML2 Assertion.", e);
        }
    }

    /**
     * Returns a SAML 2.0 based XML content representation from the {@code String} value representing the XML syntax.
     *
     * @param xmlString the {@link String} representation of the XML content
     * @return an XML object from the {@link String} value representing the XML syntax
     * @throws SSOException if an error occurs when unmarshalling the XML string representation
     */
    public static XMLObject unmarshall(String xmlString) throws SSOException {
        doBootstrap();
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setExpandEntityReferences(false);
        documentBuilderFactory.setNamespaceAware(true);
        try {
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            docBuilder.setEntityResolver(new XMLEntityResolver());
            ByteArrayInputStream is = new ByteArrayInputStream(xmlString.getBytes(Charset.forName("UTF-8")));
            Document document = docBuilder.parse(is);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (ParserConfigurationException | UnmarshallingException | SAXException | IOException e) {
            throw new SSOException("Error in unmarshalling the XML string representation.", e);
        }
    }
}
