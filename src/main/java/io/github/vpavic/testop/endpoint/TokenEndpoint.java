/*
 * Copyright 2019 the original author or authors.
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

package io.github.vpavic.testop.endpoint;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.github.benmanes.caffeine.cache.Cache;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = TokenEndpoint.PATH)
public class TokenEndpoint {

    public static final String PATH = "/token";

    private final EndpointConfiguration configuration;

    private final JwkSetProvider jwkSetProvider;

    private final Cache<AuthorizationCode, AuthenticationRequest> authorizationCodes;

    public TokenEndpoint(EndpointConfiguration configuration, JwkSetProvider jwkSetProvider,
            Cache<AuthorizationCode, AuthenticationRequest> authorizationCodes) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        Objects.requireNonNull(jwkSetProvider, "jwkSetProvider must not be null");
        Objects.requireNonNull(authorizationCodes, "authorizationCodes must not be null");
        this.configuration = configuration;
        this.jwkSetProvider = jwkSetProvider;
        this.authorizationCodes = authorizationCodes;
    }

    @PostMapping
    public void tokenEndpoint(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
        TokenResponse tokenResponse;
        try {
            TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
            AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
            if (!GrantType.AUTHORIZATION_CODE.equals(authorizationGrant.getType())) {
                throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
            }
            AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;
            AuthorizationCode authorizationCode = authorizationCodeGrant.getAuthorizationCode();
            AuthenticationRequest authenticationRequest = this.authorizationCodes.getIfPresent(authorizationCode);
            if (authenticationRequest != null) {
                this.authorizationCodes.invalidate(authorizationCode);
            }
            ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
            if ((clientAuthentication == null)
                    || !ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientAuthentication.getMethod())) {
                throw new GeneralException(OAuth2Error.INVALID_CLIENT);
            }
            if ((authenticationRequest == null)
                    || !authenticationRequest.getClientID().equals(clientAuthentication.getClientID())
                    || !authenticationRequest.getRedirectionURI().equals(authorizationCodeGrant.getRedirectionURI())) {
                throw new GeneralException(OAuth2Error.INVALID_GRANT);
            }
            Subject subject = new Subject("alice");
            SignedJWT idToken = createIdToken(authenticationRequest, subject);
            BearerAccessToken accessToken = createAccessToken(authenticationRequest, subject);
            OIDCTokens tokens = new OIDCTokens(idToken, accessToken, null);
            tokenResponse = new OIDCTokenResponse(tokens);
        }
        catch (GeneralException e) {
            tokenResponse = new TokenErrorResponse(e.getErrorObject());
        }
        catch (JOSEException e) {
            tokenResponse = new TokenErrorResponse(OAuth2Error.SERVER_ERROR);
        }
        HTTPResponse httpResponse = tokenResponse.toHTTPResponse();
        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
    }

    private SignedJWT createIdToken(AuthenticationRequest authenticationRequest, Subject subject)
            throws JOSEException, GeneralException {
        Instant now = Instant.now();
        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(this.configuration.getIssuer(), subject,
                Audience.create(authenticationRequest.getClientID().getValue()),
                Date.from(now.plus(this.configuration.idTokenLifetime())), Date.from(now));
        JWTAssertionDetails details = JWTAssertionDetails.parse(idTokenClaimsSet.toJWTClaimsSet());
        RSAKey rsaKey = (RSAKey) this.jwkSetProvider.getJwkSet().getKeys().get(0);
        return JWTAssertionFactory.create(details, JWSAlgorithm.RS256, rsaKey.toRSAPrivateKey(), rsaKey.getKeyID(),
                null);
    }

    private BearerAccessToken createAccessToken(AuthenticationRequest authenticationRequest, Subject subject)
            throws JOSEException {
        Instant now = Instant.now();
        Scope scope = authenticationRequest.getScope();
        UserInfo userInfo = new UserInfo(subject);
        userInfo.setClaim("scope", scope);
        userInfo.setClaim("client_id", authenticationRequest.getClientID());
        JWTAssertionDetails details = new JWTAssertionDetails(this.configuration.getIssuer(), subject,
                Audience.create(this.configuration.getIssuer().getValue()),
                Date.from(now.plus(this.configuration.accessTokenLifetime())), Date.from(now), Date.from(now),
                new JWTID(), userInfo.toJSONObject());
        RSAKey rsaKey = (RSAKey) this.jwkSetProvider.getJwkSet().getKeys().get(0);
        SignedJWT accessToken = JWTAssertionFactory.create(details, JWSAlgorithm.RS256, rsaKey.toRSAPrivateKey(),
                rsaKey.getKeyID(), null);
        return new BearerAccessToken(accessToken.serialize(), this.configuration.accessTokenLifetime().getSeconds(),
                scope);
    }

}
