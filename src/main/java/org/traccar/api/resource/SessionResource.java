/*
 * Copyright 2015 - 2022 Anton Tananaev (anton@traccar.org)
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

import jakarta.servlet.http.HttpServletResponse;
import org.traccar.api.BaseResource;
import org.traccar.api.security.LoginService;
import org.traccar.api.security.PermissionsService;
import org.traccar.api.signature.TokenManager;
import org.traccar.database.OpenIdProvider;
import org.traccar.database.PersistentLoginManager;
import org.traccar.helper.LogAction;
import org.traccar.helper.WebHelper;
import org.traccar.model.User;
import org.traccar.model.PersistentLogin;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import com.nimbusds.oauth2.sdk.ParseException;
import jakarta.annotation.Nullable;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.net.URI;

@Path("session")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class SessionResource extends BaseResource {

    public static final String USER_ID_KEY = "userId";
    public static final String USER_COOKIE_KEY = "user";
    public static final String PASS_COOKIE_KEY = "password";

    @Inject
    private LoginService loginService;

    @Inject
    @Nullable
    private OpenIdProvider openIdProvider;

    @Inject
    private TokenManager tokenManager;

    @Inject
    private PersistentLoginManager persistentLoginManager;

    @Context
    private HttpServletRequest request;
    @Context
    private HttpServletResponse response;


    @PermitAll
    @GET
    public User get(@QueryParam("token") String token) throws StorageException, IOException, GeneralSecurityException {

        if (token != null) {
            User user = loginService.login(token);
            if (user != null) {
                request.getSession().setAttribute(USER_ID_KEY, user.getId());
                LogAction.login(user.getId(), WebHelper.retrieveRemoteAddress(request));
                return user;
            }
        }

        Long userId = (Long) request.getSession().getAttribute(USER_ID_KEY);

        if (userId != null) {
            permissionsService.checkUserEnabled(userId);
            User user = permissionsService.getUser(userId);
            if (user != null) {
                return user;
            }
        }
        throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
    }

    public static Long rememberMeLogin(HttpServletRequest request, HttpServletResponse response,
                                       PersistentLoginManager persistentLoginManager,
                                       PermissionsService permissionsService) throws StorageException {
        Long userId = null;
        Cookie persistentCookie = getPersistentLoginCookie(request, persistentLoginManager);
        if (persistentCookie != null) {
            boolean deleteCookie = true;
            Object[] cookieValues = persistentLoginManager.parseCookieValue(persistentCookie.getValue());
            if (cookieValues != null) {
                PersistentLogin persistentLogin = persistentLoginManager.getPersistentLogin((long) cookieValues[0]);
                if (persistentLogin != null
                        && persistentLoginManager.isCookieValid(persistentLogin, (String) cookieValues[1])) {
                    if (persistentLogin.getExpiryDate().before(new Date())) {
                        persistentLoginManager.deletePersistentLogin(persistentLogin);
                    } else {
                        User user = permissionsService.getUser(persistentLogin.getUserId());
                        if (user != null) {
                            try {
                                permissionsService.checkUserEnabled(user.getId());
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

    private static Cookie getPersistentLoginCookie(HttpServletRequest request,
                                                   PersistentLoginManager persistentLoginManager) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
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
        permissionsService.checkUser(getUserId(), userId);
        User user = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", userId)));
        request.getSession().setAttribute(USER_ID_KEY, user.getId());
        LogAction.login(user.getId(), WebHelper.retrieveRemoteAddress(request));
        return user;
    }

    @PermitAll
    @POST
    public User add(
            @FormParam("email") String email, @FormParam("password") String password,
            @FormParam("rememberField") boolean rememberMe) throws StorageException {
        User user = loginService.login(email, password);
        if (user != null) {
            request.getSession().setAttribute(USER_ID_KEY, user.getId());
            LogAction.login(user.getId(), WebHelper.retrieveRemoteAddress(request));
            Cookie persistentLoginCookie = getPersistentLoginCookie(request, persistentLoginManager);
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
            LogAction.failedLogin(WebHelper.retrieveRemoteAddress(request));
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    @DELETE
    public Response remove() throws StorageException {
        LogAction.logout(getUserId(), WebHelper.retrieveRemoteAddress(request));
        request.getSession().removeAttribute(USER_ID_KEY);
        Cookie persistentLoginCookie = getPersistentLoginCookie(request, persistentLoginManager);
        if (persistentLoginCookie != null) {
            persistentLoginCookie.setMaxAge(0);
            response.addCookie(persistentLoginCookie);
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

    @PermitAll
    @Path("openid/auth")
    @GET
    public Response openIdAuth() throws IOException {
        return Response.seeOther(openIdProvider.createAuthUri()).build();
    }

    @PermitAll
    @Path("openid/callback")
    @GET
    public Response requestToken() throws IOException, StorageException, ParseException, GeneralSecurityException {
        StringBuilder requestUrl = new StringBuilder(request.getRequestURL().toString());
        String queryString = request.getQueryString();
        String requestUri = requestUrl.append('?').append(queryString).toString();

        return Response.seeOther(openIdProvider.handleCallback(URI.create(requestUri), request)).build();
    }
}
