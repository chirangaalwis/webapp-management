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

import org.wso2.appserver.webapp.security.sso.SSOConstants;
import org.wso2.appserver.webapp.security.sso.SSOException;
import org.wso2.appserver.webapp.security.sso.util.SSOUtils;

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
 * This class represents a holder of credential details for an X.509 (SSL) certificate.
 *
 * @since 6.0.0
 */
public class SSOAgentX509Credential {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private X509Certificate entityCertificate;

    public SSOAgentX509Credential(Properties keyStoreConfigurationProperties) throws SSOException {
        readX509Credentials(keyStoreConfigurationProperties);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    private void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public X509Certificate getEntityCertificate() {
        return entityCertificate;
    }

    private void setEntityCertificate(X509Certificate entityCertificate) {
        this.entityCertificate = entityCertificate;
    }

    /**
     * Reads the appropriate X.509 certificate credentials using the keystore configuration properties specified in
     * sso-sp-config.properties.
     *
     * @param keyStoreConfigurationProperties the keystore configuration properties
     * @throws SSOException if an error occurred while reading credentials
     */
    private void readX509Credentials(Properties keyStoreConfigurationProperties) throws SSOException {
        Optional generatedKeyStore = SSOUtils.generateKeyStore(keyStoreConfigurationProperties);

        if (generatedKeyStore.isPresent()) {
            KeyStore keyStore = (KeyStore) generatedKeyStore.get();
            String certificateAlias = SSOConstants.SSOAgentConfiguration.SAML2.IDP_PUBLIC_CERTIFICATE_ALIAS;
            try {
                setEntityCertificate((X509Certificate) keyStore.getCertificate(certificateAlias));
            } catch (KeyStoreException e) {
                throw new SSOException(
                        "Error occurred while retrieving public certificate with certificateAlias " + certificateAlias);
            }

            String privateKeyAlias = SSOConstants.SSOAgentConfiguration.SAML2.SP_PRIVATE_KEY_ALIAS;
            try {
                setPrivateKey((PrivateKey) keyStore.getKey(privateKeyAlias,
                        SSOConstants.SSOAgentConfiguration.SAML2.SP_PRIVATE_KEY_PASSWORD.toCharArray()));
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new SSOException("Error occurred while retrieving the private key.");
            }
            setPublicKey(getEntityCertificate().getPublicKey());
        }
    }
}
