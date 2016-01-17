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

import org.wso2.appserver.webapp.security.sso.SSOException;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Optional;

/**
 * This class defines the configuration aspects of the key store management.
 *
 * @since 6.0.0
 */
public class KeyStoreConfiguration {
    private InputStream keyStoreStream;
    private String keyStorePassword;
    private KeyStore keyStore;

    public KeyStore getKeyStore() throws SSOException {
        if (!Optional.ofNullable(keyStore).isPresent()) {
            setKeyStore(readKeyStore(getKeyStoreStream(), getKeyStorePassword()));
        }
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    private String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    private InputStream getKeyStoreStream() {
        return keyStoreStream;
    }

    public void setKeyStoreStream(InputStream keyStoreStream) {
        this.keyStoreStream = keyStoreStream;
    }

    /**
     * Returns a {@code KeyStore} from the specified {@code InputStream} using the keystore password.
     *
     * @param inputStream   the key store file {@link InputStream}
     * @param storePassword the password to the keystore
     * @return a {@link KeyStore} instance
     * @throws SSOException if an error occurs while loading the key store or if the {@code storePassword} is null
     */
    private KeyStore readKeyStore(InputStream inputStream, String storePassword) throws SSOException {
        if (!Optional.ofNullable(storePassword).isPresent()) {
            throw new SSOException("KeyStore password can not be null.");
        }
        try (InputStream keystoreInputStream = inputStream) {
            String keyStoreType = "JKS";
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(keystoreInputStream, storePassword.toCharArray());
            return keyStore;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new SSOException("Error while loading key store.", e);
        }
    }
}
