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
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = UserInfoEndpoint.PATH)
public class UserInfoEndpoint {

    public static final String PATH = "/userinfo";

    private final EndpointConfiguration configuration;

    private final JWTProcessor<SecurityContext> jwtProcessor;

    public UserInfoEndpoint(EndpointConfiguration configuration, JWTProcessor<SecurityContext> jwtProcessor) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        Objects.requireNonNull(jwtProcessor, "jwtProcessor must not be null");
        this.configuration = configuration;
        this.jwtProcessor = jwtProcessor;
    }

    @GetMapping
    public void userInfoEndpoint(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
        UserInfoResponse userInfoResponse;
        try {
            BearerAccessToken accessToken = BearerAccessToken.parse(servletRequest.getHeader("Authorization"));
            JWTClaimsSet claimsSet = JwtProcessorHelper.process(accessToken.getValue(), this.jwtProcessor);
            if (!this.configuration.getIssuer().getValue().equals(claimsSet.getIssuer())) {
                throw new GeneralException(BearerTokenError.INVALID_TOKEN);
            }
            if (!claimsSet.getAudience().contains(this.configuration.getIssuer().getValue())) {
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
