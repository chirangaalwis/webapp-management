package org.wso2.appserver.webapp.mgt.identity.sso.agent;

import org.wso2.appserver.webapp.mgt.identity.sso.agent.model.LoggedInSessionBean;

import javax.servlet.http.HttpSession;
import java.util.*;

public class SSOAgentSessionManager {

    /*
     * Session Index at the IdP is mapped to the session at the SP so that a single logout request
     * can be handled by invalidating the SP session mapped to IdP Session Index.
     */
    private static Map<String, Set<HttpSession>> ssoSessionsMap = new HashMap<>();

    /**
     * Prevents initiating the SSOAgentSessionManager class
     */
    private SSOAgentSessionManager() {
    }

    private static Map<String, Set<HttpSession>> getSSOSessionsMap() {
        return ssoSessionsMap;
    }

    private static void setSSOSessionsMap(Map<String, Set<HttpSession>> ssoSessionsMap) {
        SSOAgentSessionManager.ssoSessionsMap = ssoSessionsMap;
    }

    public static Set<HttpSession> invalidateAllSessions(HttpSession session) {
        LoggedInSessionBean sessionBean = (LoggedInSessionBean) session.getAttribute(
                SSOAgentConstants.SESSION_BEAN_NAME);
        Set<HttpSession> sessions = new HashSet<HttpSession>();
        if (sessionBean != null && sessionBean.getSAML2SSO() != null) {
            String sessionIndex = sessionBean.getSAML2SSO().getSessionIndex();
            if (sessionIndex != null) {
                sessions = ssoSessionsMap.remove(sessionIndex);
            }
        }
        if (sessions == null) {
            sessions = new HashSet<HttpSession>();
        }
        return sessions;
    }

    public static Set<HttpSession> invalidateAllSessions(String sessionIndex) {
        Set<HttpSession> sessions = ssoSessionsMap.remove(sessionIndex);
        if (sessions == null) {
            sessions = new HashSet<HttpSession>();
        }
        return sessions;
    }

    /**
     * Adds an authenticated session to the global single-sign-on (SSO) agent session manager map.
     *
     * @param session the authenticated session to be added to the session map
     */
    public static void addAuthenticatedSession(HttpSession session) {
        Optional<String> sessionIndex = Optional.ofNullable(
                ((LoggedInSessionBean) session.getAttribute(SSOAgentConstants.SESSION_BEAN_NAME)).getSAML2SSO().
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
