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
package org.wso2.appserver.webapp.security.sso.saml.signature;

import org.wso2.appserver.webapp.security.sso.SSOConstants;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.wso2.appserver.webapp.security.sso.saml.SAMLSSOUtils;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Properties;

/**
 * This class represents an entity credential associated with X.509 Public Key Infrastructure.
 *
 * @since 6.0.0
 */
public class SSOX509Credential {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private X509Certificate entityCertificate;

    public SSOX509Credential(Properties keyStoreConfigurationProperties) throws SSOException {
        readX509Credentials(keyStoreConfigurationProperties);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public X509Certificate getEntityCertificate() {
        return entityCertificate;
    }

    /**
     * Reads the appropriate X.509 certificate credentials using the keystore configuration properties specified.
     *
     * @param keyStoreConfigurationProperties the keystore configuration properties
     * @throws SSOException if an error occurred while reading credentials
     */
    private void readX509Credentials(Properties keyStoreConfigurationProperties) throws SSOException {
        Optional generatedKeyStore = SAMLSSOUtils.generateKeyStore(keyStoreConfigurationProperties);
        if (generatedKeyStore.isPresent()) {
            KeyStore keyStore = (KeyStore) generatedKeyStore.get();
            Optional<String> certificateAlias = Optional.ofNullable(keyStoreConfigurationProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.IDP_PUBLIC_CERTIFICATE_ALIAS));
            try {
                if (certificateAlias.isPresent()) {
                    entityCertificate = (X509Certificate) keyStore.getCertificate(certificateAlias.get());
                }
            } catch (KeyStoreException e) {
                throw new SSOException(
                        "Error occurred while retrieving public certificate with certificateAlias " + certificateAlias);
            }

            Optional<String> privateKeyAlias = Optional.ofNullable(keyStoreConfigurationProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.SP_PRIVATE_KEY_ALIAS));
            Optional<String> privateKeyPassword = Optional.ofNullable(keyStoreConfigurationProperties.
                    getProperty(SSOConstants.SSOAgentConfiguration.SAML2.SP_PRIVATE_KEY_PASSWORD));
            try {
                if ((privateKeyAlias.isPresent()) && (privateKeyPassword.isPresent())) {
                    privateKey = (PrivateKey) keyStore.
                            getKey(privateKeyAlias.get(), privateKeyPassword.get().toCharArray());
                }
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new SSOException("Error occurred while retrieving the private key");
            }
            publicKey = getEntityCertificate().getPublicKey();
        }
    }
}
