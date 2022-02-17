package com.lunasphere.testee;

import com.lunasphere.testee.auth.JwtRoles;
import com.lunasphere.testee.auth.JwtUtil;
import com.lunasphere.testee.auth.RequiresJwt;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

@Path("/hello")
public class HelloResource {
    @Context
    SecurityContext ctx;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Path("world")
    public String hello() {
        return "Hello, World!";
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Path("token")
    public String genToken() {
        return JwtUtil.generate();
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @JwtRoles({"USER"})
    @Path("user")
    @RequiresJwt
    public String helloUser() {
        return String.format("Hello there, %s.", ctx.getUserPrincipal().getName());
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @JwtRoles({"ADMIN"})
    @Path("admin")
    @RequiresJwt
    public String helloAdmin() {
        return String.format("Hello there, %s.\nYou are an ADMIN!", ctx.getUserPrincipal().getName());
    }
}