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

import java.text.ParseException;
import java.time.Instant;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;

final class JwtProcessorHelper {

	private JwtProcessorHelper() {
	}

	static JWTClaimsSet process(String jwtString, JWTProcessor<SecurityContext> jwtProcessor) throws GeneralException {
		JWTClaimsSet claimsSet;
		try {
			claimsSet = jwtProcessor.process(jwtString, null);
		}
		catch (ParseException | BadJOSEException | JOSEException e) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}
		if (Instant.now().isAfter(claimsSet.getExpirationTime().toInstant())) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}
		return claimsSet;
	}

}
