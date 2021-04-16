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

import java.time.Duration;

import com.nimbusds.oauth2.sdk.id.Issuer;
import org.springframework.boot.context.properties.ConfigurationProperties;

import io.github.vpavic.testop.endpoint.EndpointConfiguration;

@ConfigurationProperties("op")
public class OpenIdProviderProperties implements EndpointConfiguration {

    private Issuer issuer = new Issuer("http://localhost:8080");

    private Duration accessTokenLifetime = Duration.ofMinutes(10);

    private Duration idTokenLifetime = Duration.ofMinutes(10);

    @Override
    public Issuer getIssuer() {
        return this.issuer;
    }

    public void setIssuer(Issuer issuer) {
        this.issuer = issuer;
    }

    @Override
    public Duration accessTokenLifetime() {
        return this.accessTokenLifetime;
    }

    public void setAccessTokenLifetime(Duration accessTokenLifetime) {
        this.accessTokenLifetime = accessTokenLifetime;
    }

    @Override
    public Duration idTokenLifetime() {
        return this.idTokenLifetime;
    }

    public void setIdTokenLifetime(Duration idTokenLifetime) {
        this.idTokenLifetime = idTokenLifetime;
    }

}
