package org.wso2.appserver.webapp.mgt.identity.sso.agent;

import org.wso2.appserver.webapp.mgt.identity.sso.agent.model.LoggedInSessionBean;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SSOAgentSessionManager {

    /*
     * Session Index at the IdP is mapped to the session at the SP so that a single logout request
     * can be handled by invalidating the SP session mapped to IdP Session Index.
     */
    private static Map<String, Set<HttpSession>> ssoSessionsMap =
            new HashMap<String, Set<HttpSession>>();

    private SSOAgentSessionManager() {
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

    public static void addAuthenticatedSession(HttpSession session) {
        String sessionIndex = ((LoggedInSessionBean) session.getAttribute(
                SSOAgentConstants.SESSION_BEAN_NAME)).getSAML2SSO().getSessionIndex();
        if (ssoSessionsMap.get(sessionIndex) != null) {
            ssoSessionsMap.get(sessionIndex).add(session);
        } else {
            Set<HttpSession> sessions = new HashSet<HttpSession>();
            sessions.add(session);
            ssoSessionsMap.put(sessionIndex, sessions);
        }
    }

}
