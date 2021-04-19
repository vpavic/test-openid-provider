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
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.github.benmanes.caffeine.cache.Cache;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.server.ResponseStatusException;

@Controller
@RequestMapping(path = AuthorizationEndpoint.PATH)
public class AuthorizationEndpoint {

	public static final String PATH = "/authorize";

	private final Cache<AuthorizationCode, AuthenticationRequest> authorizationCodes;

	public AuthorizationEndpoint(Cache<AuthorizationCode, AuthenticationRequest> authorizationCodes) {
		Objects.requireNonNull(authorizationCodes, "authorizationCodes must not be null");
		this.authorizationCodes = authorizationCodes;
	}

	@GetMapping
	public void authorizationEndpoint(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
			throws IOException {
		AuthorizationResponse authorizationResponse;
		try {
			AuthenticationRequest authorizationRequest = AuthenticationRequest.parse(servletRequest.getQueryString());
			if (!authorizationRequest.getResponseType().impliesCodeFlow()) {
				throw new GeneralException(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
			}
			AuthorizationCode authorizationCode = new AuthorizationCode();
			this.authorizationCodes.put(authorizationCode, authorizationRequest);
			authorizationResponse = new AuthenticationSuccessResponse(authorizationRequest.getRedirectionURI(),
					authorizationCode, null, null, authorizationRequest.getState(), null, ResponseMode.QUERY);
		}
		catch (GeneralException e) {
			if (e.getRedirectionURI() != null) {
				authorizationResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), e.getErrorObject(),
						e.getState(), e.getResponseMode());
			}
			else {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
			}
		}
		HTTPResponse httpResponse = authorizationResponse.toHTTPResponse();
		ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
	}

}
