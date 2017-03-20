/*
 * Copyright 2015 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.api.resource;

import org.traccar.Context;
import org.traccar.api.BaseResource;
import org.traccar.database.PersistentLoginManager;
import org.traccar.model.PersistentLogin;
import org.traccar.model.User;

import javax.annotation.security.PermitAll;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.sql.SQLException;
import java.util.Date;

@Path("session")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class SessionResource extends BaseResource {

    public static final String USER_ID_KEY = "userId";

    @javax.ws.rs.core.Context
    private HttpServletRequest request;

    @javax.ws.rs.core.Context
    private HttpServletResponse response;

    @PermitAll
    @GET
    public User get(@QueryParam("token") String token) throws SQLException, UnsupportedEncodingException {
        Long userId = (Long) request.getSession().getAttribute(USER_ID_KEY);

        if (userId != null) {
            Context.getPermissionsManager().checkUserEnabled(userId);
            return Context.getPermissionsManager().getUser(userId);
        } else {
            throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
        }
    }

    public static Long rememberMeLogin(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        Long userId = null;
        Cookie persistentCookie = getPersistentLoginCookie(request);
        if (persistentCookie != null) {
            boolean deleteCookie = true;
            PersistentLoginManager persistentLoginManager = Context.getPersistentLoginManager();
            Object[] cookieValues = persistentLoginManager.parseCookieValue(persistentCookie.getValue());
            if (cookieValues != null) {
                PersistentLogin persistentLogin = persistentLoginManager.getPersistentLogin((long) cookieValues[0]);
                if (persistentLogin != null
                        && persistentLoginManager.isCookieValid(persistentLogin, (String) cookieValues[1])) {
                    if (persistentLogin.getExpiryDate().before(new Date())) {
                        persistentLoginManager.deletePersistentLogin(persistentLogin);
                    } else {
                        User user = Context.getPermissionsManager().getUser(persistentLogin.getUserId());
                        if (user != null) {
                            try {
                                Context.getPermissionsManager().checkUserEnabled(user.getId());
                                deleteCookie = false;
                            } catch (SecurityException exception) {
                                deleteCookie = true;
                            }
                            if (!deleteCookie) {
                                userId = user.getId();
                                request.getSession().setAttribute(USER_ID_KEY, userId);
                                persistentLogin.setLastUsed(new Date());
                                persistentLoginManager.updatePersistentLogin(persistentLogin);
                            }
                        }
                    }
                }
            }
            if (deleteCookie) {
                persistentCookie.setMaxAge(0);
                response.addCookie(persistentCookie);
            }
        }
        return userId;
    }

    private static Cookie getPersistentLoginCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            String persistentLoginCookieName = Context.getPersistentLoginManager().getCookieName();
            for (int i = 0; i < cookies.length; i++) {
                if (cookies[i].getName().equals(persistentLoginCookieName)) {
                    return cookies[i];
                }
            }
        }
        return null;
    }

    @PermitAll
    @POST
    public User add(
            @FormParam("email") String email, @FormParam("password") String password,
            @FormParam("rememberField") boolean rememberMe) throws SQLException {
        User user = Context.getPermissionsManager().login(email, password);
        if (user != null) {
            request.getSession().setAttribute(USER_ID_KEY, user.getId());
            Cookie persistentLoginCookie = getPersistentLoginCookie(request);
            if (rememberMe) {
                if (persistentLoginCookie != null) {
                    Context.getPersistentLoginManager().deletePersistentLogin(persistentLoginCookie.getValue());
                }

                PersistentLogin persistentLogin = Context.getPersistentLoginManager().createPersistentLogin(user);
                persistentLoginCookie = new Cookie(Context.getPersistentLoginManager().getCookieName(),
                        Context.getPersistentLoginManager().getCookieValue(persistentLogin));
                persistentLoginCookie.setMaxAge(Context.getPersistentLoginManager().getExpiryDays() * 24 * 60 * 60);
                response.addCookie(persistentLoginCookie);
            } else if (persistentLoginCookie != null) {
                Context.getPersistentLoginManager().deletePersistentLogin(persistentLoginCookie.getValue());
                persistentLoginCookie.setMaxAge(0);
                response.addCookie(persistentLoginCookie);
            }

            return user;
        } else {
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    @DELETE
    public Response remove() throws SQLException {
        request.getSession().removeAttribute(USER_ID_KEY);
        Cookie persistentLoginCookie = getPersistentLoginCookie(request);
        if (persistentLoginCookie != null) {
            persistentLoginCookie.setMaxAge(0);
            response.addCookie(persistentLoginCookie);
            Context.getPersistentLoginManager().deletePersistentLogin(persistentLoginCookie.getValue());
        }
        return Response.noContent().build();
    }

}
