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

import com.nimbusds.oauth2.sdk.id.Issuer;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

@ConfigurationProperties("testop")
public class TestOpenIdProviderProperties {

    private Issuer issuer = new Issuer("http://localhost:8080");

    private Resource jwkSet = new ClassPathResource("jwks.json");

    public Issuer getIssuer() {
        return this.issuer;
    }

    public void setIssuer(Issuer issuer) {
        this.issuer = issuer;
    }

    public Resource getJwkSet() {
        return this.jwkSet;
    }

    public void setJwkSet(Resource jwkSet) {
        this.jwkSet = jwkSet;
    }

}
