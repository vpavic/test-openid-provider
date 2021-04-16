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

package io.github.vpavic.testop.config;

import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.testop.endpoint.JwkSetProvider;

@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
public class OpenIdProviderConfiguration {

    private final JWKSet jwkSet;

    public OpenIdProviderConfiguration() {
        this.jwkSet = initJwkSet();
    }

    private static JWKSet initJwkSet() {
        RSAKey rsaKey;
        try {
            rsaKey = new RSAKeyGenerator(2048) //
                    .keyUse(KeyUse.SIGNATURE) //
                    .algorithm(JWSAlgorithm.RS256) //
                    .keyID(new Identifier().getValue()) //
                    .generate();
        }
        catch (JOSEException ex) {
            throw new RuntimeException(ex);
        }
        return new JWKSet(rsaKey);
    }

    @Bean
    public JwkSetProvider jwkSetProvider() {
        return () -> this.jwkSet;
    }

    @Bean
    public DefaultJWTProcessor<SecurityContext> jwtProcessor() {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(this.jwkSet));
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }

    @Bean
    public Cache<AuthorizationCode, AuthenticationRequest> authorizationCodes() {
        return Caffeine.newBuilder() //
                .maximumSize(10_000) //
                .expireAfterWrite(5, TimeUnit.MINUTES) //
                .build();
    }

}
