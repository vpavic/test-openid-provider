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

import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties(TestOpenIdProviderProperties.class)
public class TestOpenIdProviderApplication {

    private final TestOpenIdProviderProperties properties;

    public TestOpenIdProviderApplication(TestOpenIdProviderProperties properties) {
        this.properties = properties;
    }

    public static void main(String[] args) {
        SpringApplication.run(TestOpenIdProviderApplication.class, args);
    }

    @Bean
    public Issuer issuer() {
        return this.properties.getIssuer();
    }

    @Bean
    public JWKSet jwkSet() throws IOException, ParseException {
        return JWKSet.load(this.properties.getJwkSet().getInputStream());
    }

    @Bean
    public DefaultJWTProcessor<SecurityContext> jwtProcessor(JWKSet jwkSet) {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(jwkSet));
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }

    @Bean
    public Cache<AuthorizationCode, AuthenticationRequest> authorizationCodes() {
        return Caffeine.newBuilder().maximumSize(10).expireAfterWrite(Duration.ofMinutes(5)).build();
    }

}
