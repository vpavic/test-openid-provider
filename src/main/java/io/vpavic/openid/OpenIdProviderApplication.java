/*
 * Copyright 2018 the original author or authors.
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

package io.vpavic.openid;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
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
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.server.ResponseStatusException;

@SpringBootApplication
@EnableConfigurationProperties(OpenIdProviderProperties.class)
@Controller
public class OpenIdProviderApplication {

    private static final Cache<AuthorizationCode, AuthenticationRequest> authorizationCodes = Caffeine.newBuilder()
            .maximumSize(10).expireAfterWrite(Duration.ofMinutes(5)).build();

    private final Issuer issuer;

    private final JWKSet jwkSet;

    public OpenIdProviderApplication(OpenIdProviderProperties properties) throws IOException, ParseException {
        this.issuer = properties.getIssuer();
        this.jwkSet = JWKSet.load(properties.getJwkSet().getInputStream());
    }

    public static void main(String[] args) {
        SpringApplication.run(OpenIdProviderApplication.class, args);
    }

    @GetMapping(path = "/.well-known/openid-configuration")
    public ResponseEntity<String> discoveryEndpoint() {
        OIDCProviderMetadata providerMetadata = new OIDCProviderMetadata(this.issuer,
                Collections.singletonList(SubjectType.PUBLIC), providerUri("/jwks.json"));
        providerMetadata.setAuthorizationEndpointURI(providerUri("/authorize"));
        providerMetadata.setTokenEndpointURI(providerUri("/token"));
        providerMetadata.setScopes(new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL));
        providerMetadata.setResponseTypes(Collections.singletonList(ResponseType.getDefault()));
        providerMetadata.setResponseModes(Collections.singletonList(ResponseMode.QUERY));
        providerMetadata.setGrantTypes(Collections.singletonList(GrantType.AUTHORIZATION_CODE));
        providerMetadata
                .setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.getDefault()));
        providerMetadata.setUserInfoEndpointURI(providerUri("/userinfo"));
        providerMetadata.setIDTokenJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
        providerMetadata.setClaimTypes(Collections.singletonList(ClaimType.NORMAL));
        return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON_UTF8)
                .body(providerMetadata.toString());
    }

    private URI providerUri(String path) {
        return URI.create(this.issuer.getValue() + path);
    }

    @GetMapping(path = "/jwks.json")
    public ResponseEntity<String> jwkSetEndpoint() {
        return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.parseMediaType(JWKSet.MIME_TYPE))
                .body(this.jwkSet.toString());
    }

    @GetMapping(path = "/authorize")
    public void authorizationEndpoint(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws IOException {
        AuthorizationResponse authorizationResponse;
        try {
            AuthenticationRequest authorizationRequest = AuthenticationRequest.parse(servletRequest.getQueryString());
            if (!authorizationRequest.getResponseType().impliesCodeFlow()) {
                throw new GeneralException(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
            }
            AuthorizationCode authorizationCode = new AuthorizationCode();
            authorizationCodes.put(authorizationCode, authorizationRequest);
            authorizationResponse = new AuthenticationSuccessResponse(authorizationRequest.getRedirectionURI(),
                    authorizationCode, null, null, authorizationRequest.getState(), null, ResponseMode.QUERY);
        }
        catch (GeneralException e) {
            if (e.getRedirectionURI() != null) {
                authorizationResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), e.getErrorObject(),
                        e.getState(), e.getResponseMode());
            }
            else {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
            }
        }
        HTTPResponse httpResponse = authorizationResponse.toHTTPResponse();
        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
    }

    @PostMapping(path = "/token")
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
            AuthenticationRequest authenticationRequest = authorizationCodes.getIfPresent(authorizationCode);
            if (authenticationRequest != null) {
                authorizationCodes.invalidate(authorizationCode);
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
        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(this.issuer, subject,
                Audience.create(authenticationRequest.getClientID().getValue()),
                Date.from(now.plus(10, ChronoUnit.MINUTES)), Date.from(now));
        JWTAssertionDetails details = JWTAssertionDetails.parse(idTokenClaimsSet.toJWTClaimsSet());
        RSAKey rsaKey = (RSAKey) this.jwkSet.getKeys().get(0);
        return JWTAssertionFactory.create(details, JWSAlgorithm.RS256, rsaKey.toRSAPrivateKey(), rsaKey.getKeyID(),
                null);
    }

    private BearerAccessToken createAccessToken(AuthenticationRequest authenticationRequest, Subject subject)
            throws JOSEException {
        Instant now = Instant.now();
        Duration lifetime = Duration.ofMinutes(10);
        Scope scope = authenticationRequest.getScope();
        UserInfo userInfo = new UserInfo(subject);
        userInfo.setClaim("scope", scope);
        userInfo.setClaim("client_id", authenticationRequest.getClientID());
        JWTAssertionDetails details = new JWTAssertionDetails(this.issuer, subject,
                Audience.create(this.issuer.getValue()), Date.from(now.plus(lifetime)), Date.from(now), Date.from(now),
                new JWTID(), userInfo.toJSONObject());
        RSAKey rsaKey = (RSAKey) this.jwkSet.getKeys().get(0);
        SignedJWT accessToken = JWTAssertionFactory.create(details, JWSAlgorithm.RS256, rsaKey.toRSAPrivateKey(),
                rsaKey.getKeyID(), null);
        return new BearerAccessToken(accessToken.serialize(), lifetime.getSeconds(), scope);
    }

    @GetMapping(path = "/userinfo")
    public void userInfoEndpoint(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
        UserInfoResponse userInfoResponse;
        try {
            BearerAccessToken accessToken = BearerAccessToken.parse(servletRequest.getHeader("Authorization"));
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                    new ImmutableJWKSet<>(this.jwkSet));
            jwtProcessor.setJWSKeySelector(keySelector);
            JWTClaimsSet claimsSet;
            try {
                claimsSet = jwtProcessor.process(accessToken.getValue(), null);
            }
            catch (ParseException | BadJOSEException | JOSEException e) {
                throw new GeneralException(BearerTokenError.INVALID_TOKEN);
            }
            if (!this.issuer.getValue().equals(claimsSet.getIssuer())) {
                throw new GeneralException(BearerTokenError.INVALID_TOKEN);
            }
            if (!claimsSet.getAudience().contains(this.issuer.getValue())) {
                throw new GeneralException(BearerTokenError.INVALID_TOKEN);
            }
            if (Instant.now().isAfter(claimsSet.getExpirationTime().toInstant())) {
                throw new GeneralException(BearerTokenError.INVALID_TOKEN);
            }
            try {
                Scope scope = Scope.parse(claimsSet.getStringListClaim("scope"));
                Subject subject = new Subject(claimsSet.getSubject());
                UserInfo userInfo = new UserInfo(subject);
                if (scope.contains(OIDCScopeValue.PROFILE)) {
                    userInfo.setName("Alice");
                }
                if (scope.contains(OIDCScopeValue.EMAIL)) {
                    userInfo.setEmailAddress("alice@example.com");
                }
                userInfoResponse = new UserInfoSuccessResponse(userInfo);
            }
            catch (ParseException e) {
                throw new GeneralException(BearerTokenError.INVALID_TOKEN);
            }
        }
        catch (GeneralException e) {
            userInfoResponse = new UserInfoErrorResponse(e.getErrorObject());
        }
        HTTPResponse httpResponse = userInfoResponse.toHTTPResponse();
        httpRequest.setHeader("Access-Control-Allow-Origin", "*");
        httpRequest.setHeader("Access-Control-Allow-Methods", "GET");
        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
    }

}
