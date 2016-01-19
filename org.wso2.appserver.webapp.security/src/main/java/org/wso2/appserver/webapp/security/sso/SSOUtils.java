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
package org.wso2.appserver.webapp.security.sso;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Optional;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * This class contains general utility functions used within the org.wso2.appserver.webapp.security.sso.
 *
 * @since 6.0.0
 */
public class SSOUtils {
    private static final Logger logger = Logger.getLogger(SSOUtils.class.getName());
    private static final Random random = new Random();

    private static Random getRandom() {
        return random;
    }

    public static Logger getLogger() {
        return logger;
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
    public static Path getCatalinaConfigurationHome() throws SSOException {
        return Paths.
                get(getCatalinaBase().toString(), SSOConstants.SAMLSSOValveConstants.TOMCAT_CONFIGURATION_FOLDER_NAME);
    }

    /**
     * Loads the property content defined in the specified file to the specified {@code Properties} data structure.
     *
     * @param properties the {@link Properties} structure to which the file content is to be loaded
     * @param filePath   the {@link Path} to the file from which properties are to be loaded
     * @throws SSOException if an error occurs during the loading of the file content or if the specified file cannot
     *                      be found
     */
    public static void loadPropertiesFromFile(Properties properties, Path filePath) throws SSOException {
        if (Files.exists(filePath)) {
            try (InputStream fileInputStream = Files.newInputStream(filePath)) {
                properties.load(fileInputStream);
                getLogger().log(Level.INFO, "Successfully loaded the properties from the file");
            } catch (IOException e) {
                throw new SSOException("Error when loading properties from the specified file " + filePath);
            }
        } else {
            throw new SSOException("File specified by " + filePath + " does not exist");
        }
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
     * Returns true if the specified {@code Collection} is null or empty, else false.
     *
     * @param collection the {@link Collection} to be checked
     * @return true if the specified {@code Collection} is null or empty, else false
     */
    public static boolean isCollectionEmpty(Collection collection) {
        return ((!Optional.ofNullable(collection).isPresent()) || (collection.isEmpty()));
    }

}
