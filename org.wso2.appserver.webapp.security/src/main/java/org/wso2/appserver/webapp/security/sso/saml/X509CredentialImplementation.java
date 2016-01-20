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

import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.appserver.webapp.security.sso.SSOException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import javax.crypto.SecretKey;

/**
 * This class represents an entity credential associated with X.509 Public Key Infrastructure.
 * <p>
 * This class implements the org.opensaml.xml.security.x509.X509Credential interface.
 *
 * @since 6.0.0
 */
public class X509CredentialImplementation implements X509Credential {
    private PublicKey publicKey;
    private X509Certificate entityCertificate;
    private PrivateKey privateKey;

    public X509CredentialImplementation(X509Certificate certificate) {
        setPublicKey(certificate.getPublicKey());
        setEntityCertificate(certificate);
    }

    public X509CredentialImplementation(SSOX509Credential credential) throws SSOException {
        setPublicKey(credential.getPublicKey());
        setEntityCertificate(credential.getEntityCertificate());
        setPrivateKey(credential.getPrivateKey());
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    private void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    private void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public X509Certificate getEntityCertificate() {
        return entityCertificate;
    }

    private void setEntityCertificate(X509Certificate entityCertificate) {
        this.entityCertificate = entityCertificate;
    }

    /**
     * Following methods are not implemented.
     */

    @Override
    public Collection<X509CRL> getCRLs() {
        return new ArrayList<>();
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        return new ArrayList<>();
    }

    @Override
    public CredentialContextSet getCredentalContextSet() {
        return null;
    }

    @Override
    public Class<? extends Credential> getCredentialType() {
        return null;
    }

    @Override
    public String getEntityId() {
        return null;
    }

    @Override
    public Collection<String> getKeyNames() {
        return new ArrayList<>();
    }

    @Override
    public SecretKey getSecretKey() {
        return null;
    }

    @Override
    public UsageType getUsageType() {
        return null;
    }
}
