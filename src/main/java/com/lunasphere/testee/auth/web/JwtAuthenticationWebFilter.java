package com.lunasphere.testee.auth.web;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.lunasphere.testee.auth.JwtContext;
import com.lunasphere.testee.auth.JwtUtil;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Provider
public class JwtAuthenticationWebFilter implements Filter {

    private String REQUIRED_ROLE;
    private List<String> WHITELIST = Arrays.asList("/login.html", "/error.html", "/api/hello/world", "/api/hello/token");

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        REQUIRED_ROLE = filterConfig.getInitParameter("role-name");
        Filter.super.init(filterConfig);
    }

    private String extractToken(HttpServletRequest req) {
        String token = req.getHeader(HttpHeaders.AUTHORIZATION);

        if (token != null) {
            token = token.replaceFirst("Bearer ", "");
        }

        return token;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        String jwt = extractToken(req);

        if (jwt != null) {
            System.out.println("Token found! - Decoding...");
            try {
                JwtContext userContext = JwtUtil.decode(jwt);
                servletRequest.setAttribute("User", userContext);

                if (REQUIRED_ROLE.isEmpty() || userContext.isUserInRole(REQUIRED_ROLE)) {
                    filterChain.doFilter(servletRequest, servletResponse);
                    return;
                }
            } catch (JWTVerificationException ex) {
                System.err.println("Token invalid! - Error: " + ex.getMessage());
            }

            // The token provided was not valid in some way, UNAUTHORISED response.
//            res.sendError(401, "JWT Submitted was invalid, or do you not have permission to access this resource.");
//            return;
        } else if (WHITELIST.stream().anyMatch(entry -> req.getRequestURI().toLowerCase().contains(entry))) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        /*
         There isn't a token!! The user probably didn't mean to go here?
         Redirect to the login page.
        */
        res.sendRedirect("/login.html");
    }
}
