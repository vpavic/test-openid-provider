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

import java.util.Objects;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = JwkSetEndpoint.PATH)
public class JwkSetEndpoint {

    static final String PATH = "/jwks.json";

    private final String serializedJwkSet;

    public JwkSetEndpoint(JWKSet jwkSet) {
        Objects.requireNonNull(jwkSet, "jwkSet must not be null");
        this.serializedJwkSet = jwkSet.toString();
    }

    @GetMapping
    public ResponseEntity<String> jwkSetEndpoint() {
        return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.parseMediaType(JWKSet.MIME_TYPE))
                .body(this.serializedJwkSet);
    }

}
