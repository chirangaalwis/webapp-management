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

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

//  TODO: ANALYZE, COMMENTS
public class X509CredentialImpl implements X509Credential {

    private PublicKey publicKey = null;
    private X509Certificate entityCertificate = null;
    private PrivateKey privateKey = null;

    public X509CredentialImpl(X509Certificate cert) {
        publicKey = cert.getPublicKey();
        this.entityCertificate = cert;
    }

    public X509CredentialImpl(SSOAgentX509Credential credential) throws SSOException {
        publicKey = credential.getPublicKey();
        this.entityCertificate = credential.getEntityCertificate();
        this.privateKey = credential.getPrivateKey();
    }

    /**
     * Retrieves the publicKey
     */
    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public X509Certificate getEntityCertificate() {
        return entityCertificate;
    }

    // ********** Not implemented **************************************************************

    @Override
    public Collection<X509CRL> getCRLs() {
        return new ArrayList<X509CRL>();
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        return new ArrayList<X509Certificate>();
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
        return new ArrayList<String>();
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
