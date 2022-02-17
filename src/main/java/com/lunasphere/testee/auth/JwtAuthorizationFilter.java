package com.lunasphere.testee.auth;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

@Provider
@Priority(Priorities.AUTHORIZATION)
@JwtRoles
public class JwtAuthorizationFilter implements ContainerRequestFilter {
    @Context
    private HttpServletRequest httpRequest;

    @Context
    ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestCtx) {
//        SecurityContext ctx = requestCtx.getSecurityContext();
        JwtContext ctx = (JwtContext) httpRequest.getAttribute("User");
        requestCtx.setSecurityContext(ctx);

        JwtRoles rolesAllowed = resourceInfo.getResourceMethod().getAnnotation(JwtRoles.class);
        if (rolesAllowed == null)
            rolesAllowed = resourceInfo.getResourceClass().getAnnotation(JwtRoles.class);

        if (rolesAllowed == null)
            return;

        for (String role : rolesAllowed.value()) {
            if (ctx.isUserInRole(role)) {
                return;
            }
        }
        requestCtx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
    }
}
