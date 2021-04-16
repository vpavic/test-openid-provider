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

import java.net.URI;
import java.util.Collections;
import java.util.Objects;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = "/.well-known/openid-configuration")
public class DiscoveryEndpoint {

    private final EndpointConfiguration configuration;

    private String serializedProviderMetadata;

    public DiscoveryEndpoint(EndpointConfiguration configuration) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        this.configuration = configuration;
    }

    @GetMapping
    public ResponseEntity<String> discoveryEndpoint() {
        if (this.serializedProviderMetadata == null) {
            this.serializedProviderMetadata = buildProviderMetadata(this.configuration.getIssuer());
        }
        return ResponseEntity.status(HttpStatus.OK) //
                .contentType(MediaType.APPLICATION_JSON) //
                .body(this.serializedProviderMetadata);
    }

    private static String buildProviderMetadata(Issuer issuer) {
        OIDCProviderMetadata providerMetadata = new OIDCProviderMetadata(issuer,
                Collections.singletonList(SubjectType.PUBLIC), URI.create(issuer.getValue() + JwkSetEndpoint.PATH));
        providerMetadata.setAuthorizationEndpointURI(URI.create(issuer.getValue() + AuthorizationEndpoint.PATH));
        providerMetadata.setTokenEndpointURI(URI.create(issuer.getValue() + TokenEndpoint.PATH));
        providerMetadata.setIntrospectionEndpointURI(URI.create(issuer.getValue() + TokenIntrospectionEndpoint.PATH));
        providerMetadata.setScopes(new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL));
        providerMetadata.setResponseTypes(Collections.singletonList(ResponseType.getDefault()));
        providerMetadata.setResponseModes(Collections.singletonList(ResponseMode.QUERY));
        providerMetadata.setGrantTypes(Collections.singletonList(GrantType.AUTHORIZATION_CODE));
        providerMetadata
                .setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.getDefault()));
        providerMetadata.setUserInfoEndpointURI(URI.create(issuer.getValue() + UserInfoEndpoint.PATH));
        providerMetadata.setIDTokenJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
        providerMetadata.setClaimTypes(Collections.singletonList(ClaimType.NORMAL));
        return providerMetadata.toString();
    }

}
