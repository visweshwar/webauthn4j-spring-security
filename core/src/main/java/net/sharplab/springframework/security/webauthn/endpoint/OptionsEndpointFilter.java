/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.registry.Registry;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OptionsEndpointFilter extends GenericFilterBean {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/options";

    //~ Instance fields
    // ================================================================================================
    /**
     * Url this filter should get activated on.
     */
    /**
     * Url this filter should get activated on.
     */
    protected String filterProcessesUrl = FILTER_URL;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    protected Registry registry;

    private AuthenticationTrustResolver trustResolver;
    private MFATokenEvaluator mfaTokenEvaluator;

    private OptionsProvider optionsProvider;

    public OptionsEndpointFilter(OptionsProvider optionsProvider, Registry registry) {
        this.optionsProvider = optionsProvider;
        this.registry = registry;
        this.trustResolver = new AuthenticationTrustResolverImpl();
        this.mfaTokenEvaluator = new MFATokenEvaluatorImpl();
        checkConfig();
    }

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        Assert.notNull(filterProcessesUrl, "filterProcessesUrl must not be null");
        Assert.notNull(registry, "registry must not be null");
        Assert.notNull(trustResolver, "trustResolver must not be null");
        Assert.notNull(mfaTokenEvaluator, "mfaTokenEvaluator must not be null");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Options options = processRequest(fi.getRequest());
            writeResponse(fi.getResponse(), new Response<>(options));
        } catch (RuntimeException e) {
            logger.debug("RuntimeException is thrown", e);
            writeErrorResponse(fi.getResponse(), e);
        }

    }

    Options processRequest(HttpServletRequest request) {
        String loginUsername = getLoginUsername();
        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(request, loginUsername, null);
        AssertionOptions assertionOptions = optionsProvider.getAssertionOptions(request, loginUsername, null);
        return new Options(
                attestationOptions.getRelyingParty(),
                attestationOptions.getUser(),
                attestationOptions.getChallenge(),
                attestationOptions.getPubKeyCredParams(),
                attestationOptions.getRegistrationTimeout(),
                assertionOptions.getAuthenticationTimeout(),
                attestationOptions.getCredentials(),
                attestationOptions.getRegistrationExtensions(),
                assertionOptions.getAuthenticationExtensions(),
                assertionOptions.getParameters()
                );
    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    public MFATokenEvaluator getMFATokenEvaluator() {
        return mfaTokenEvaluator;
    }

    public void setMFATokenEvaluator(MFATokenEvaluator mfaTokenEvaluator) {
        this.mfaTokenEvaluator = mfaTokenEvaluator;
    }


    /**
     * The filter will be used in case the URL of the request contains the FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    private boolean processFilter(HttpServletRequest request) {
        return (request.getRequestURI().contains(filterProcessesUrl));
    }

    void writeResponse(HttpServletResponse httpServletResponse, Response response) throws IOException {
        String responseText = registry.getJsonMapper().writeValueAsString(response);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(responseText);
    }

    void writeErrorResponse(HttpServletResponse httpServletResponse, RuntimeException e) throws IOException {
        Response errorResponse;
        int statusCode;
        if (e instanceof InsufficientAuthenticationException) {
            errorResponse = new Response("Anonymous access is prohibited");
            statusCode = HttpServletResponse.SC_FORBIDDEN;
        } else {
            errorResponse = new Response("The server encountered an internal error" + e.getMessage() + "\n" + e.getStackTrace().toString());
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        String errorResponseText = registry.getJsonMapper().writeValueAsString(errorResponse);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(errorResponseText);
        httpServletResponse.setStatus(statusCode);
    }

    String getLoginUsername(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (trustResolver.isAnonymous(authentication) && !mfaTokenEvaluator.isMultiFactorAuthentication(authentication)) {
            return null;
        }
        else {
            return authentication.getName();
        }
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
    }
}
