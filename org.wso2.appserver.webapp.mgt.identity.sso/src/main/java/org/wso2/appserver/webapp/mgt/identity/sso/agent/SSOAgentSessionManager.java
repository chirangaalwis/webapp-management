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


    //  TODO: JAVADOC COMMENTS
    public static Set<HttpSession> invalidateAllSessions(HttpSession session) {
        LoggedInSessionBean sessionBean = (LoggedInSessionBean) session.
                getAttribute(SSOAgentConstants.SESSION_BEAN_NAME);
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
