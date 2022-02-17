package com.lunasphere.testee.auth;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class JwtContext implements SecurityContext {
    private static final String AUTH_SCHEME = "JWT";

    String name;
    Set<String> roles;
    boolean secure;

    public JwtContext(String name, String authGroup) {
        this.name = name;
        this.roles = new HashSet<>();
        roles.add("USER");
        if (authGroup.equals("ADMIN"))
            roles.add("ADMIN");
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    @Override
    public Principal getUserPrincipal() {
        return () -> name;
    }

    @Override
    public boolean isUserInRole(String s) {
        return roles.contains(s);
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public String getAuthenticationScheme() {
        return AUTH_SCHEME;
    }
}
