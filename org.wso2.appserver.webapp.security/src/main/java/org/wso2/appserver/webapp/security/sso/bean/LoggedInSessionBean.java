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
package org.wso2.appserver.webapp.security.sso.bean;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.wso2.appserver.webapp.security.sso.saml.SAMLSSOUtils;

import java.io.IOException;
import java.io.Serializable;
import java.util.Map;
import java.util.Optional;
import javax.xml.bind.annotation.XmlAttribute;

/**
 * A Java Bean class which represents a user logged-in session.
 *
 * @since 6.0.0
 */
public class LoggedInSessionBean implements Serializable {
    private static final long serialVersionUID = 1639369078633501892L;
    private static final String emptyString = "";

    private SAML2SSO saml2SSO;

    public SAML2SSO getSAML2SSO() {
        return saml2SSO;
    }

    public void setSAML2SSO(SAML2SSO saml2SSO) {
        this.saml2SSO = saml2SSO;
    }

    /**
     * A nested static class which represents an access token.
     */
    public static class AccessTokenResponseBean implements Serializable {
        private static final long serialVersionUID = -3976452423669184620L;

        @XmlAttribute(name = "access_token")
        @SerializedName("access_token")
        private String accessToken;

        @XmlAttribute(name = "refresh_token")
        @SerializedName("refresh_token")
        private String refreshToken;

        @XmlAttribute(name = "token_type")
        @SerializedName("token_type")
        private String tokenType;

        @XmlAttribute(name = "expires_in")
        @SerializedName("expires_in")
        private String expiresIn;

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }

        public String getTokenType() {
            return tokenType;
        }

        public void setTokenType(String tokenType) {
            this.tokenType = tokenType;
        }

        public String getExpiresIn() {
            return expiresIn;
        }

        public void setExpiresIn(String expiresIn) {
            this.expiresIn = expiresIn;
        }

        /**
         * Serializes this {@code AccessTokenResponseBean} object to its JSON representation.
         *
         * @return the serialized {@link String} form of the JSON representation of this object
         */
        public String serialize() {
            Gson gson = new Gson();
            return gson.toJson(this);
        }

        /**
         * Deserialize the {@code accessTokenResponseBeanString} JSON representation to its
         * {@code AccessTokenResponseBean} form.
         *
         * @param accessTokenResponseBeanString the {@link String} JSON representation to be deserialized
         * @return the deserialized object
         */
        public AccessTokenResponseBean deSerialize(String accessTokenResponseBeanString) {
            Gson gson = new Gson();
            return gson.fromJson(accessTokenResponseBeanString, AccessTokenResponseBean.class);
        }
    }

    /**
     * A static nested class which represents the SAML 2.0 specific single-sign-on (SSO) details to be held
     * in a user logged-in session.
     */
    public static class SAML2SSO implements Serializable {
        private static final long serialVersionUID = -2832436047480647011L;

        private String subjectId;
        private Response response;
        private String responseString;
        private Assertion assertion;
        private String assertionString;
        private AccessTokenResponseBean accessTokenResponseBean;
        private String sessionIndex;
        private Map<String, String> subjectAttributes;

        public String getSubjectId() {
            return subjectId;
        }

        public void setSubjectId(String subjectId) {
            this.subjectId = subjectId;
        }

        public Map<String, String> getSubjectAttributes() {
            return subjectAttributes;
        }

        public void setSubjectAttributes(Map<String, String> samlSSOAttributes) {
            this.subjectAttributes = samlSSOAttributes;
        }

        public String getSessionIndex() {
            return sessionIndex;
        }

        public void setSessionIndex(String sessionIndex) {
            this.sessionIndex = sessionIndex;
        }

        public Response getSAMLResponse() {
            return response;
        }

        public void setSAMLResponse(Response samlResponse) {
            this.response = samlResponse;
        }

        public String getResponseString() {
            return responseString;
        }

        public void setResponseString(String responseString) {
            this.responseString = responseString;
        }

        public Assertion getAssertion() {
            return assertion;
        }

        public void setAssertion(Assertion samlAssertion) {
            this.assertion = samlAssertion;
        }

        public String getAssertionString() {
            return assertionString;
        }

        public void setAssertionString(String samlAssertionString) {
            this.assertionString = samlAssertionString;
        }

        public AccessTokenResponseBean getAccessTokenResponseBean() {
            return accessTokenResponseBean;
        }

        public void setAccessTokenResponseBean(AccessTokenResponseBean accessTokenResponseBean) {
            this.accessTokenResponseBean = accessTokenResponseBean;
        }

        //  These are the two default methods which would be executed during the serialization and deserialization
        //  process of a LoggedInSessionBean instance

        /**
         * Writes this {@code LoggedInSessionBean} instance to the specified {@code ObjectOutputStream}.
         * </p>
         * This is the default {@code writeObject} method executed during the serialization process of this instance.
         *
         * @param stream the {@link java.io.ObjectOutputStream} to which this LoggedInSessionBean instance is to be
         *               written
         * @throws IOException if there are I/O errors while writing to the underlying stream
         */
        private void writeObject(java.io.ObjectOutputStream stream) throws IOException {
            stream.writeObject(getSubjectId());
            stream.writeObject(getResponseString());
            stream.writeObject(getAssertionString());
            stream.writeObject(getSessionIndex());
            if (Optional.ofNullable(getAccessTokenResponseBean()).isPresent()) {
                stream.writeObject(getAccessTokenResponseBean().serialize());
            } else {
                stream.writeObject(emptyString);
            }
            stream.writeObject(getSubjectAttributes());
        }

        /**
         * Reads this {@code LoggedInSessionBean} instance to the specified {@code ObjectInputStream}.
         * </p>
         * This is the default {@code readObject} method executed during the deSerialization process of this instance.
         *
         * @param stream the serialized {@link java.io.ObjectInputStream} from which the LoggedInSessionBean instance is
         *               to be read
         * @throws IOException            if I/O errors occurred while reading from the underlying stream
         * @throws ClassNotFoundException if class definition of a serialized object is not found
         * @throws SSOException           if an error occurs during unmarshalling
         */
        private void readObject(java.io.ObjectInputStream stream)
                throws IOException, ClassNotFoundException, SSOException {
            setSubjectId((String) stream.readObject());

            setResponseString((String) stream.readObject());
            if ((Optional.ofNullable(getResponseString()).isPresent()) && (!emptyString.equals(getResponseString()))) {
                setSAMLResponse((Response) SAMLSSOUtils.unmarshall(getResponseString()));
            }

            setAssertionString((String) stream.readObject());
            if ((Optional.ofNullable(getResponseString()).isPresent()) && (!emptyString.
                    equals(getAssertionString()))) {
                setAssertion((Assertion) SAMLSSOUtils.unmarshall(assertionString));
            }

            setSessionIndex((String) stream.readObject());
            String accessTokenResponseBeanString = (String) stream.readObject();
            if (!emptyString.equals(accessTokenResponseBeanString)) {
                setAccessTokenResponseBean(getAccessTokenResponseBean().deSerialize(accessTokenResponseBeanString));
            } else {
                setAccessTokenResponseBean(null);
            }
            setSubjectAttributes((Map<String, String>) stream.readObject());
        }
    }
}
