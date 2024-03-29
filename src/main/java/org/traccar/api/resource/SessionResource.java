/*
 * Copyright 2015 - 2021 Anton Tananaev (anton@traccar.org)
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

import org.traccar.Main;
import org.traccar.api.BaseResource;
import org.traccar.api.security.LoginService;
import org.traccar.api.signature.TokenManager;
import org.traccar.database.PersistentLoginManager;
import org.traccar.helper.DataConverter;
import org.traccar.helper.LogAction;
import org.traccar.helper.ServletHelper;
import org.traccar.model.PersistentLogin;
import org.traccar.model.User;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import javax.annotation.security.PermitAll;
import javax.inject.Inject;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Date;

@Path("session")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class SessionResource extends BaseResource {

    public static final String USER_ID_KEY = "userId";

    @Inject
    private LoginService loginService;

    @Inject
    private TokenManager tokenManager;

    @javax.ws.rs.core.Context
    private HttpServletRequest request;

    @javax.ws.rs.core.Context
    private HttpServletResponse response;

    @PermitAll
    @GET
    public User get(@QueryParam("token") String token) throws StorageException, IOException, GeneralSecurityException {

        if (token != null) {
            User user = loginService.login(token);
            if (user != null) {
                request.getSession().setAttribute(USER_ID_KEY, user.getId());
                LogAction.login(user.getId(), ServletHelper.retrieveRemoteAddress(request));
                return user;
            }
        }

        Long userId = (Long) request.getSession().getAttribute(USER_ID_KEY);
        if (userId != null) {
            return permissionsService.getUser(userId);
        }

        throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
    }

    public static Long rememberMeLogin(HttpServletRequest request, HttpServletResponse response) throws SQLException, StorageException {
        Long userId = null;
        Cookie persistentCookie = getPersistentLoginCookie(request);
        if (persistentCookie != null) {
            boolean deleteCookie = true;
            PersistentLoginManager persistentLoginManager = Main.getInjector().getInstance(PersistentLoginManager.class);
            Object[] cookieValues = persistentLoginManager.parseCookieValue(persistentCookie.getValue());
            if (cookieValues != null) {
                PersistentLogin persistentLogin = persistentLoginManager.getPersistentLogin((long) cookieValues[0]);
                if (persistentLogin != null
                        && persistentLoginManager.isCookieValid(persistentLogin, (String) cookieValues[1])) {
                    if (persistentLogin.getExpiryDate().before(new Date())) {
                        persistentLoginManager.deletePersistentLogin(persistentLogin);
                    } else {
                        User user = persistentLoginManager.getUser(persistentLogin.getUserId());
                        if (user != null) {
                            try {
                                persistentLoginManager.checkUserEnabled(user);
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
            PersistentLoginManager persistentLoginManager = Main.getInjector().getInstance(PersistentLoginManager.class);
            String persistentLoginCookieName = persistentLoginManager.getCookieName();
            for (int i = 0; i < cookies.length; i++) {
                if (cookies[i].getName().equals(persistentLoginCookieName)) {
                    return cookies[i];
                }
            }
        }
        return null;
    }

    @Path("{id}")
    @GET
    public User get(@PathParam("id") long userId) throws StorageException {
        permissionsService.checkAdmin(getUserId());
        User user = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", userId)));
        request.getSession().setAttribute(USER_ID_KEY, user.getId());
        LogAction.login(user.getId(), ServletHelper.retrieveRemoteAddress(request));
        return user;
    }

    @PermitAll
    @POST
    public User add(
            @FormParam("email") String email, @FormParam("password") String password,
            @FormParam("rememberField") boolean rememberMe) throws StorageException, SQLException {
        User user = loginService.login(email, password);
        if (user != null) {
            request.getSession().setAttribute(USER_ID_KEY, user.getId());
            LogAction.login(user.getId(), ServletHelper.retrieveRemoteAddress(request));
            Cookie persistentLoginCookie = getPersistentLoginCookie(request);
            PersistentLoginManager persistentLoginManager = Main.getInjector().getInstance(PersistentLoginManager.class);
            if (rememberMe) {
                if (persistentLoginCookie != null) {
                    persistentLoginManager.deletePersistentLogin(persistentLoginCookie.getValue());
                }

                PersistentLogin persistentLogin = persistentLoginManager.createPersistentLogin(user);
                persistentLoginCookie = new Cookie(persistentLoginManager.getCookieName(),
                        persistentLoginManager.getCookieValue(persistentLogin));
                persistentLoginCookie.setMaxAge(persistentLoginManager.getExpiryDays() * 24 * 60 * 60);
                response.addCookie(persistentLoginCookie);
            } else if (persistentLoginCookie != null) {
                persistentLoginManager.deletePersistentLogin(persistentLoginCookie.getValue());
                persistentLoginCookie.setMaxAge(0);
                response.addCookie(persistentLoginCookie);
            }
            return user;
        } else {
            LogAction.failedLogin(ServletHelper.retrieveRemoteAddress(request));
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    @DELETE
    public Response remove() throws SQLException, StorageException {
        LogAction.logout(getUserId(), ServletHelper.retrieveRemoteAddress(request));
        request.getSession().removeAttribute(USER_ID_KEY);
        Cookie persistentLoginCookie = getPersistentLoginCookie(request);
        if (persistentLoginCookie != null) {
            persistentLoginCookie.setMaxAge(0);
            response.addCookie(persistentLoginCookie);
            PersistentLoginManager persistentLoginManager = Main.getInjector().getInstance(PersistentLoginManager.class);
            persistentLoginManager.deletePersistentLogin(persistentLoginCookie.getValue());
        }
        return Response.noContent().build();
    }

    @Path("token")
    @POST
    public String requestToken(
            @FormParam("expiration") Date expiration) throws StorageException, GeneralSecurityException, IOException {
        return tokenManager.generateToken(getUserId(), expiration);
    }

}
