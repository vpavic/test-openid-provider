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

package io.github.vpavic.testop;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class TestOpenIdProviderApplicationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestOpenIdProviderProperties properties;

    private Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PROFILE);

    private ClientID clientId = new ClientID("test-client");

    private Secret clientSecret = new Secret("secret");

    private URI redirectUri = URI.create("http://example.com");

    private State state = new State();

    private Subject subject = new Subject("alice");

    @Test
    public void authorizationCodeFlow() throws Exception {
        // authorization request
        AuthenticationRequest authorizationRequest = new AuthenticationRequest.Builder(new ResponseType(Value.CODE),
                this.scope, this.clientId, this.redirectUri).state(this.state)
                        .endpointURI(endpointUri(AuthorizationEndpoint.PATH)).build();
        HTTPRequest authorizationHttpRequest = authorizationRequest.toHTTPRequest();
        authorizationHttpRequest.setFollowRedirects(false);
        AuthenticationSuccessResponse authorizationResponse = AuthenticationSuccessResponse
                .parse(authorizationHttpRequest.send());
        assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(this.redirectUri);
        assertThat(authorizationResponse.getState()).isEqualTo(this.state);
        // token request
        TokenRequest tokenRequest = new TokenRequest(endpointUri(TokenEndpoint.PATH),
                new ClientSecretBasic(this.clientId, this.clientSecret),
                new AuthorizationCodeGrant(authorizationResponse.getAuthorizationCode(), this.redirectUri));
        OIDCTokenResponse tokenResponse = OIDCTokenResponse.parse(tokenRequest.toHTTPRequest().send());
        OIDCTokens tokens = tokenResponse.getOIDCTokens();
        AccessToken accessToken = tokens.getAccessToken();
        JWT idToken = tokens.getIDToken();
        assertThat(accessToken.getScope()).isEqualTo(this.scope);
        assertThat(idToken.getJWTClaimsSet().getIssuer()).isEqualTo(this.properties.getIssuer().getValue());
        assertThat(idToken.getJWTClaimsSet().getSubject()).isEqualTo(this.subject.getValue());
        // introspection request
        TokenIntrospectionRequest tokenIntrospectionRequest = new TokenIntrospectionRequest(
                endpointUri(TokenIntrospectionEndpoint.PATH), accessToken);
        HTTPRequest tokenIntrospectionHttpRequest = tokenIntrospectionRequest.toHTTPRequest();
        tokenIntrospectionHttpRequest.setAuthorization("Bearer secret");
        TokenIntrospectionSuccessResponse tokenIntrospectionResponse = TokenIntrospectionSuccessResponse
                .parse(tokenIntrospectionHttpRequest.send());
        assertThat(tokenIntrospectionResponse.isActive()).isEqualTo(true);
        assertThat(tokenIntrospectionResponse.getScope()).isEqualTo(this.scope);
        assertThat(tokenIntrospectionResponse.getClientID()).isEqualTo(this.clientId);
        assertThat(tokenIntrospectionResponse.getSubject()).isEqualTo(this.subject);
        assertThat(tokenIntrospectionResponse.getIssuer()).isEqualTo(this.properties.getIssuer());
        // userinfo request
        UserInfoRequest userInfoRequest = new UserInfoRequest(endpointUri(UserInfoEndpoint.PATH),
                (BearerAccessToken) accessToken);
        UserInfoSuccessResponse userInfoResponse = UserInfoSuccessResponse
                .parse(userInfoRequest.toHTTPRequest().send());
        assertThat(userInfoResponse.getUserInfo().getSubject()).isEqualTo(this.subject);
        assertThat(userInfoResponse.getUserInfo().getEmailAddress()).isEqualTo("alice@example.com");
        assertThat(userInfoResponse.getUserInfo().getName()).isEqualTo("Alice");
    }

    private URI endpointUri(String path) {
        return URI.create("http://localhost:" + this.port + "/" + path);
    }

}
