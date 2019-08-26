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
import java.text.ParseException;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = TokenIntrospectionEndpoint.PATH)
public class TokenIntrospectionEndpoint {

    public static final String PATH = "/introspect";

    private final JWTProcessor<SecurityContext> jwtProcessor;

    public TokenIntrospectionEndpoint(JWTProcessor<SecurityContext> jwtProcessor) {
        Objects.requireNonNull(jwtProcessor, "jwtProcessor must not be null");
        this.jwtProcessor = jwtProcessor;
    }

    @PostMapping
    public void introspectEndpoint(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
        TokenIntrospectionResponse tokenIntrospectionResponse;
        try {
            TokenIntrospectionRequest tokenIntrospectionRequest = TokenIntrospectionRequest.parse(httpRequest);
            AccessToken clientAuthorization = tokenIntrospectionRequest.getClientAuthorization();
            if (clientAuthorization == null) {
                throw new GeneralException(OAuth2Error.INVALID_CLIENT);
            }
            Token token = tokenIntrospectionRequest.getToken();
            if (token instanceof RefreshToken) {
                tokenIntrospectionResponse = new TokenIntrospectionSuccessResponse.Builder(false).build();
            }
            else {
                try {
                    BearerAccessToken accessToken = new BearerAccessToken(token.getValue());
                    JWTClaimsSet claimsSet = JwtProcessorHelper.process(accessToken.getValue(), this.jwtProcessor);
                    tokenIntrospectionResponse = new TokenIntrospectionSuccessResponse.Builder(true)
                            .scope(Scope.parse(claimsSet.getStringListClaim("scope")))
                            .clientID(new ClientID(claimsSet.getStringClaim("client_id")))
                            .tokenType(AccessTokenType.BEARER).expirationTime(claimsSet.getExpirationTime())
                            .issueTime(claimsSet.getIssueTime()).notBeforeTime(claimsSet.getNotBeforeTime())
                            .subject(new Subject(claimsSet.getSubject()))
                            .audience(Audience.create(claimsSet.getAudience()))
                            .issuer(new Issuer(claimsSet.getIssuer())).jwtID(new JWTID(claimsSet.getJWTID())).build();
                }
                catch (ParseException | GeneralException e) {
                    tokenIntrospectionResponse = new TokenIntrospectionSuccessResponse.Builder(false).build();
                }
            }
        }
        catch (GeneralException e) {
            tokenIntrospectionResponse = new TokenIntrospectionErrorResponse(e.getErrorObject());
        }
        HTTPResponse httpResponse = tokenIntrospectionResponse.toHTTPResponse();
        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
    }

}
