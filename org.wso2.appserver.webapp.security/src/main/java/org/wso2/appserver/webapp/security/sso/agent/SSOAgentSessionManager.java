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
package org.wso2.appserver.webapp.security.sso.agent;

import org.wso2.appserver.webapp.security.sso.SSOConstants;
import org.wso2.appserver.webapp.security.sso.bean.LoggedInSession;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.servlet.http.HttpSession;

/**
 * A class which manages authenticated sessions of a service provider.
 *
 * @since 6.0.0
 */
public class SSOAgentSessionManager {
    /**
     * Session Index at the identity provider is mapped to the session at the service provider so that a single-logout
     * request (SLO) can be handled by invalidating the service provider session mapped to identity provider session
     * index.
     */
    private static Map<String, Set<HttpSession>> ssoSessionsMap = new HashMap<>();

    /**
     * Prevents initiating the SSOAgentSessionManager class.
     */
    private SSOAgentSessionManager() {
    }

    private static Map<String, Set<HttpSession>> getSSOSessionsMap() {
        return ssoSessionsMap;
    }

    /**
     * Invalidates all the sessions associated with the session index corresponding to the specified {@code HttpSession}
     * from the global single-sign-on (SSO) agent session manager map.
     *
     * @param session the {@link HttpSession} instance
     * @return set of sessions associated with the session index
     */
    public static Set<HttpSession> invalidateAllSessions(HttpSession session) {
        LoggedInSession sessionBean = (LoggedInSession) session.
                getAttribute(SSOConstants.SESSION_BEAN_NAME);
        Set<HttpSession> sessions = new HashSet<>();
        if ((Optional.ofNullable(sessionBean).isPresent()) && (Optional.ofNullable(sessionBean.getSAML2SSO()).
                isPresent())) {
            String sessionIndex = sessionBean.getSAML2SSO().getSessionIndex();
            if (Optional.ofNullable(sessionIndex).isPresent()) {
                sessions = getSSOSessionsMap().remove(sessionIndex);
            }
        }
        sessions = Optional.ofNullable(sessions).orElse(new HashSet<>());
        return sessions;
    }

    /**
     * Invalidates all the sessions associated with a specified session index from the global single-sign-on (SSO)
     * agent session manager map.
     *
     * @param sessionIndex the session index of whom all sessions are to be invalidated
     * @return set of sessions associated with the session index
     */
    public static Set<HttpSession> invalidateAllSessions(String sessionIndex) {
        Set<HttpSession> sessions = getSSOSessionsMap().remove(sessionIndex);
        sessions = Optional.ofNullable(sessions).orElse(new HashSet<>());
        return sessions;
    }

    /**
     * Adds an authenticated session to the global single-sign-on (SSO) agent session manager map.
     *
     * @param session the authenticated session to be added to the session map
     */
    public static void addAuthenticatedSession(HttpSession session) {
        Optional<String> sessionIndex = Optional.
                ofNullable(((LoggedInSession) session.getAttribute(SSOConstants.SESSION_BEAN_NAME)).getSAML2SSO().
                        getSessionIndex());

        if (Optional.ofNullable(getSSOSessionsMap().get(sessionIndex.get())).isPresent()) {
            getSSOSessionsMap().get(sessionIndex.get()).add(session);
        } else {
            Set<HttpSession> sessions = new HashSet<>();
            sessions.add(session);
            getSSOSessionsMap().put(sessionIndex.get(), sessions);
        }
    }
}
