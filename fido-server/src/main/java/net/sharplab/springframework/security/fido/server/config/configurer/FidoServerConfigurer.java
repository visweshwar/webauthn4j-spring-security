/*
 * Copyright 2002-2019 the original author or authors.
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

package net.sharplab.springframework.security.fido.server.config.configurer;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.ExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import net.sharplab.springframework.security.fido.server.endpoint.*;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnConfigurerUtil;
import net.sharplab.springframework.security.webauthn.options.OptionsProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FidoServerConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<FidoServerConfigurer<H>, H> {


    private final FidoServerAttestationOptionsEndpointConfig fidoServerAttestationOptionsEndpointConfig = new FidoServerAttestationOptionsEndpointConfig();
    private final FidoServerAttestationResultEndpointConfig fidoServerAttestationResultEndpointConfig = new FidoServerAttestationResultEndpointConfig();
    private final FidoServerAssertionOptionsEndpointConfig fidoServerAssertionOptionsEndpointConfig = new FidoServerAssertionOptionsEndpointConfig();
    private final FidoServerAssertionResultEndpointConfig fidoServerAssertionResultEndpointConfig = new FidoServerAssertionResultEndpointConfig();
    //~ Instance fields
    // ================================================================================================
    private OptionsProvider optionsProvider;
    private JsonConverter jsonConverter;

    private String rpId = null;
    private String rpName = null;
    private String rpIcon = null;
    private Long registrationTimeout;
    private Long authenticationTimeout;
    private final PublicKeyCredParamsConfig publicKeyCredParamsConfig = new PublicKeyCredParamsConfig();
    private final ExtensionsClientInputsConfig<RegistrationExtensionClientInput> registrationExtensionsConfig
            = new ExtensionsClientInputsConfig<>();
    private final ExtensionsClientInputsConfig<AuthenticationExtensionClientInput> authenticationExtensionsConfig
            = new ExtensionsClientInputsConfig<>();

    public static FidoServerConfigurer<HttpSecurity> fidoServer() {
        return new FidoServerConfigurer<>();
    }

    @SuppressWarnings("Duplicates")
    @Override
    public void configure(H http) throws Exception {
        super.configure(http);
        if (optionsProvider == null) {
            optionsProvider = WebAuthnConfigurerUtil.getOptionsProvider(http);
        }
        http.setSharedObject(OptionsProvider.class, optionsProvider);
        if (jsonConverter == null) {
            jsonConverter = WebAuthnConfigurerUtil.getJsonConverter(http);
        }
        http.setSharedObject(JsonConverter.class, jsonConverter);


        if (rpId != null) {
            optionsProvider.setRpId(rpId);
        }
        if (rpName != null) {
            optionsProvider.setRpName(rpName);
        }
        if (rpIcon != null) {
            optionsProvider.setRpIcon(rpIcon);
        }
        optionsProvider.getPubKeyCredParams().addAll(publicKeyCredParamsConfig.publicKeyCredentialParameters);
        if (registrationTimeout != null) {
            optionsProvider.setRegistrationTimeout(registrationTimeout);
        }
        if (authenticationTimeout != null) {
            optionsProvider.setAuthenticationTimeout(authenticationTimeout);
        }
        optionsProvider.setRegistrationExtensions(new AuthenticationExtensionsClientInputs<>(registrationExtensionsConfig.extensionsClientInputs));
        optionsProvider.setAuthenticationExtensions(new AuthenticationExtensionsClientInputs<>(authenticationExtensionsConfig.extensionsClientInputs));

        fidoServerAttestationOptionsEndpointConfig.configure(http);
        fidoServerAttestationResultEndpointConfig.configure(http);
        fidoServerAssertionOptionsEndpointConfig.configure(http);
        fidoServerAssertionResultEndpointConfig.configure(http);
    }

    /**
     * The relying party id for credential scoping
     * @param rpId the relying party id
     * @return the {@link FidoServerConfigurer} for additional customization
     */
    public FidoServerConfigurer<H> rpId(String rpId) {
        Assert.hasText(rpId, "rpId parameter must not be null or empty");
        this.rpId = rpId;
        return this;
    }

    /**
     * The relying party name
     * @param rpName the relying party name
     * @return the {@link FidoServerConfigurer} for additional customization
     */
    public FidoServerConfigurer<H> rpName(String rpName) {
        Assert.hasText(rpName, "rpName parameter must not be null or empty");
        this.rpName = rpName;
        return this;
    }

    /**
     * The relying party icon
     * @param rpIcon the relying party icon
     * @return the {@link FidoServerConfigurer} for additional customization
     */
    public FidoServerConfigurer<H> rpIcon(String rpIcon) {
        Assert.hasText(rpIcon, "rpIcon parameter must not be null or empty");
        this.rpIcon = rpIcon;
        return this;
    }

    /**
     * Returns the {@link FidoServerConfigurer.PublicKeyCredParamsConfig} for configuring PublicKeyCredParams
     * @return the {@link FidoServerConfigurer.PublicKeyCredParamsConfig}
     */
    public FidoServerConfigurer<H>.PublicKeyCredParamsConfig publicKeyCredParams() {
        return this.publicKeyCredParamsConfig;
    }

    /**
     * The timeout for registration ceremony
     * @param registrationTimeout the timeout for registration ceremony
     * @return the {@link FidoServerConfigurer} for additional customization
     */
    public FidoServerConfigurer<H> registrationTimeout(Long registrationTimeout) {
        this.registrationTimeout = registrationTimeout;
        return this;
    }

    /**
     * The timeout for authentication ceremony
     * @param authenticationTimeout the timeout for authentication ceremony
     * @return the {@link FidoServerConfigurer} for additional customization
     */
    public FidoServerConfigurer<H> authenticationTimeout(Long authenticationTimeout) {
        this.authenticationTimeout = authenticationTimeout;
        return this;
    }

    /**
     * Returns the {@link FidoServerConfigurer.ExtensionsClientInputsConfig} for configuring registration extensions
     * @return the {@link FidoServerConfigurer.ExtensionsClientInputsConfig}
     */
    public ExtensionsClientInputsConfig<RegistrationExtensionClientInput> registrationExtensions(){
        return this.registrationExtensionsConfig;
    }

    /**
     * Returns the {@link FidoServerConfigurer.ExtensionsClientInputsConfig} for configuring authentication extensions
     * @return the {@link FidoServerConfigurer.ExtensionsClientInputsConfig}
     */
    public ExtensionsClientInputsConfig<AuthenticationExtensionClientInput> authenticationExtensions(){
        return this.authenticationExtensionsConfig;
    }

    public FidoServerAttestationOptionsEndpointConfig fidoServerAttestationOptionsEndpoint() {
        return this.fidoServerAttestationOptionsEndpointConfig;
    }

    public FidoServerAttestationResultEndpointConfig fidoServerAttestationResultEndpoint() {
        return this.fidoServerAttestationResultEndpointConfig;
    }

    public FidoServerAssertionOptionsEndpointConfig fidoServerAssertionOptionsEndpoint() {
        return this.fidoServerAssertionOptionsEndpointConfig;
    }

    public FidoServerAssertionResultEndpointConfig fidoServerAssertionResultEndpoint() {
        return this.fidoServerAssertionResultEndpointConfig;
    }

    public FidoServerConfigurer<H> optionsProvider(OptionsProvider optionsProvider) {
        Assert.notNull(optionsProvider, "optionsProvider must not be null");
        this.optionsProvider = optionsProvider;
        return this;
    }

    public FidoServerConfigurer<H> jsonConverter(JsonConverter jsonConverter) {
        Assert.notNull(jsonConverter, "jsonConverter must not be null");
        this.jsonConverter = jsonConverter;
        return this;
    }

    /**
     * Configuration options for PublicKeyCredParams
     */
    public class PublicKeyCredParamsConfig {

        private PublicKeyCredParamsConfig(){}

        private List<PublicKeyCredentialParameters> publicKeyCredentialParameters = new ArrayList<>();

        /**
         * Add PublicKeyCredParam
         * @param type the {@link PublicKeyCredentialType}
         * @param alg the {@link COSEAlgorithmIdentifier}
         * @return the {@link PublicKeyCredParamsConfig}
         */
        public PublicKeyCredParamsConfig addPublicKeyCredParams(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg) {
            Assert.notNull(type, "type must not be null");
            Assert.notNull(alg, "alg must not be null");

            publicKeyCredentialParameters.add(new PublicKeyCredentialParameters(type, alg));
            return this;
        }

        /**
         * Returns the {@link FidoServerConfigurer} for further configuration.
         *
         * @return the {@link FidoServerConfigurer}
         */
        public FidoServerConfigurer<H> and() {
            return FidoServerConfigurer.this;
        }

    }

    /**
     * Configuration options for AuthenticationExtensionsClientInputs
     */
    public class ExtensionsClientInputsConfig<T extends ExtensionClientInput> {

        private ExtensionsClientInputsConfig(){}

        private Map<String, T> extensionsClientInputs = new HashMap<>();

        /**
         * Add AuthenticationExtensionClientInput
         * @param extensionClientInput the T
         * @return the {@link FidoServerConfigurer.ExtensionsClientInputsConfig}
         */
        public ExtensionsClientInputsConfig<T> addExtension(T extensionClientInput){
            Assert.notNull(extensionClientInput, "extensionClientInput must not be null");
            extensionsClientInputs.put(extensionClientInput.getIdentifier(), extensionClientInput);
            return this;
        }

        /**
         * Returns the {@link FidoServerConfigurer} for further configuration.
         *
         * @return the {@link FidoServerConfigurer}
         */
        public FidoServerConfigurer<H> and() {
            return FidoServerConfigurer.this;
        }
    }

    public class FidoServerAttestationOptionsEndpointConfig extends AbstractServerEndpointConfig<FidoServerAttestationOptionsEndpointFilter> {

        FidoServerAttestationOptionsEndpointConfig() {
            super(FidoServerAttestationOptionsEndpointFilter.class);
        }

        @Override
        protected FidoServerAttestationOptionsEndpointFilter createInstance() {
            return new FidoServerAttestationOptionsEndpointFilter(jsonConverter, optionsProvider);
        }
    }

    public class FidoServerAttestationResultEndpointConfig extends AbstractServerEndpointConfig<FidoServerAttestationResultEndpointFilter> {

        private WebAuthnUserDetailsService webAuthnUserDetailsService;
        private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;
        private UsernameNotFoundHandler usernameNotFoundHandler;
        private final ExpectedRegistrationExtensionIdsConfig
                expectedRegistrationExtensionIdsConfig = new ExpectedRegistrationExtensionIdsConfig();

        FidoServerAttestationResultEndpointConfig() {
            super(FidoServerAttestationResultEndpointFilter.class);
        }

        @Override
        void configure(H http) {
            super.configure(http);
            if (webAuthnUserDetailsService == null) {
                webAuthnUserDetailsService = WebAuthnConfigurerUtil.getWebAuthnUserDetailsService(http);
            }
            http.setSharedObject(WebAuthnUserDetailsService.class, webAuthnUserDetailsService);
            if (webAuthnRegistrationRequestValidator == null) {
                webAuthnRegistrationRequestValidator = WebAuthnConfigurerUtil.getWebAuthnRegistrationRequestValidator(http);
            }

            if (expectedRegistrationExtensionIdsConfig.expectedAuthenticationExtensionIds.isEmpty()) {
                webAuthnRegistrationRequestValidator.setExpectedRegistrationExtensionIds(new ArrayList<>(optionsProvider.getAuthenticationExtensions().keySet()));
            } else {
                webAuthnRegistrationRequestValidator.setExpectedRegistrationExtensionIds(expectedRegistrationExtensionIdsConfig.expectedAuthenticationExtensionIds);
            }

            http.setSharedObject(WebAuthnRegistrationRequestValidator.class, webAuthnRegistrationRequestValidator);
        }

        public FidoServerAttestationResultEndpointConfig webAuthnUserDetailsService(WebAuthnUserDetailsService webAuthnUserDetailsService) {
            Assert.notNull(webAuthnUserDetailsService, "webAuthnUserDetailsService must not be null");
            this.webAuthnUserDetailsService = webAuthnUserDetailsService;
            return this;
        }

        public FidoServerAttestationResultEndpointConfig webAuthnRegistrationRequestValidator(WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator) {
            Assert.notNull(webAuthnRegistrationRequestValidator, "webAuthnRegistrationRequestValidator must not be null");
            this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;
            return this;
        }

        public FidoServerAttestationResultEndpointConfig usernameNotFoundHandler(UsernameNotFoundHandler usernameNotFoundHandler) {
            Assert.notNull(usernameNotFoundHandler, "usernameNotFoundHandler must not be null");
            this.usernameNotFoundHandler = usernameNotFoundHandler;
            return this;
        }

        public ExpectedRegistrationExtensionIdsConfig expectedAuthenticationExtensionIds(){
            return expectedRegistrationExtensionIdsConfig;
        }

        @Override
        protected FidoServerAttestationResultEndpointFilter createInstance() {
            FidoServerAttestationResultEndpointFilter filter = new FidoServerAttestationResultEndpointFilter(jsonConverter, webAuthnUserDetailsService, webAuthnRegistrationRequestValidator);
            filter.setUsernameNotFoundHandler(usernameNotFoundHandler);
            return filter;
        }

        /**
         * Configuration options for expectedRegistrationExtensionIds
         */
        public class ExpectedRegistrationExtensionIdsConfig {

            private ExpectedRegistrationExtensionIdsConfig(){}

            private List<String> expectedAuthenticationExtensionIds = new ArrayList<>();

            /**
             * Add AuthenticationExtensionClientInput
             * @param expectedRegistrationExtensionId the expected registration extension id
             * @return the {@link ExpectedRegistrationExtensionIdsConfig}
             */
            public ExpectedRegistrationExtensionIdsConfig add(String expectedRegistrationExtensionId){
                Assert.notNull(expectedRegistrationExtensionId, "expectedRegistrationExtensionId must not be null");
                expectedAuthenticationExtensionIds.add(expectedRegistrationExtensionId);
                return this;
            }

            /**
             * Returns the {@link FidoServerAttestationResultEndpointConfig} for further configuration.
             *
             * @return the {@link FidoServerAttestationResultEndpointConfig}
             */
            public FidoServerAttestationResultEndpointConfig and() {
                return FidoServerAttestationResultEndpointConfig.this;
            }
        }
    }

    public class FidoServerAssertionOptionsEndpointConfig extends AbstractServerEndpointConfig<FidoServerAssertionOptionsEndpointFilter> {

        FidoServerAssertionOptionsEndpointConfig() {
            super(FidoServerAssertionOptionsEndpointFilter.class);
        }

        @Override
        protected FidoServerAssertionOptionsEndpointFilter createInstance() {
            return new FidoServerAssertionOptionsEndpointFilter(jsonConverter, optionsProvider);
        }
    }

    private class FidoServerAssertionResultEndpointConfig {

        private String filterProcessingUrl = null;
        private AuthenticationManager authenticationManager;
        private ServerPropertyProvider serverPropertyProvider = null;
        private final FidoServerAssertionResultEndpointConfig.ExpectedAuthenticationExtensionIdsConfig
                expectedAuthenticationExtensionIdsConfig = new FidoServerAssertionResultEndpointConfig.ExpectedAuthenticationExtensionIdsConfig();


        FidoServerAssertionResultEndpointConfig() {
        }

        void configure(H http) {

            if (authenticationManager == null) {
                authenticationManager = http.getSharedObject(AuthenticationManager.class);
            }
            http.setSharedObject(AuthenticationManager.class, authenticationManager);

            FidoServerAssertionResultEndpointFilter serverEndpointFilter;

            if (serverPropertyProvider == null) {
                serverPropertyProvider = WebAuthnConfigurerUtil.getServerPropertyProvider(http);
            }
            http.setSharedObject(ServerPropertyProvider.class, serverPropertyProvider);

            ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
            String[] beanNames = applicationContext.getBeanNamesForType(FidoServerAssertionResultEndpointFilter.class);
            if (beanNames.length == 0) {
                serverEndpointFilter = new FidoServerAssertionResultEndpointFilter(jsonConverter, serverPropertyProvider);
                if (filterProcessingUrl != null) {
                    serverEndpointFilter.setFilterProcessesUrl(filterProcessingUrl);
                }
            } else {
                serverEndpointFilter = applicationContext.getBean(FidoServerAssertionResultEndpointFilter.class);
            }

            serverEndpointFilter.setAuthenticationManager(authenticationManager);

            if (expectedAuthenticationExtensionIdsConfig.expectedAuthenticationExtensionIds.isEmpty()) {
                serverEndpointFilter.setExpectedAuthenticationExtensionIds(new ArrayList<>(optionsProvider.getAuthenticationExtensions().keySet()));
            } else {
                serverEndpointFilter.setExpectedAuthenticationExtensionIds(expectedAuthenticationExtensionIdsConfig.expectedAuthenticationExtensionIds);
            }

            http.setSharedObject(FidoServerAssertionResultEndpointFilter.class, serverEndpointFilter);
            http.addFilterAfter(serverEndpointFilter, UsernamePasswordAuthenticationFilter.class);
        }


        public FidoServerAssertionResultEndpointConfig serverPropertyProvider(ServerPropertyProvider serverPropertyProvider) {
            this.serverPropertyProvider = serverPropertyProvider;
            return this;
        }

        public FidoServerAssertionResultEndpointConfig processingUrl(String processingUrl) {
            this.filterProcessingUrl = processingUrl;
            return this;
        }

        public FidoServerAssertionResultEndpointConfig.ExpectedAuthenticationExtensionIdsConfig expectedAuthenticationExtensionIds(){
            return expectedAuthenticationExtensionIdsConfig;
        }

        public FidoServerConfigurer<H> and() {
            return FidoServerConfigurer.this;
        }

        /**
         * Configuration options for expectedAuthenticationExtensionIds
         */
        public class ExpectedAuthenticationExtensionIdsConfig {

            private ExpectedAuthenticationExtensionIdsConfig(){}

            private List<String> expectedAuthenticationExtensionIds = new ArrayList<>();

            /**
             * Add AuthenticationExtensionClientInput
             * @param expectedAuthenticationExtensionId the expected authentication extension id
             * @return the {@link FidoServerAssertionResultEndpointConfig.ExpectedAuthenticationExtensionIdsConfig}
             */
            public ExpectedAuthenticationExtensionIdsConfig add(String expectedAuthenticationExtensionId){
                Assert.notNull(expectedAuthenticationExtensionId, "expectedAuthenticationExtensionId must not be null");
                expectedAuthenticationExtensionIds.add(expectedAuthenticationExtensionId);
                return this;
            }

            /**
             * Returns the {@link FidoServerAssertionResultEndpointConfig} for further configuration.
             *
             * @return the {@link FidoServerAssertionResultEndpointConfig}
             */
            public FidoServerAssertionResultEndpointConfig and() {
                return FidoServerAssertionResultEndpointConfig.this;
            }
        }

    }

    public abstract class AbstractServerEndpointConfig<F extends ServerEndpointFilterBase> {

        private Class<F> filterClass;
        private String filterProcessingUrl = null;

        AbstractServerEndpointConfig(Class<F> filterClass) {
            this.filterClass = filterClass;
        }

        void configure(H http) {
            F serverEndpointFilter;
            ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
            String[] beanNames = applicationContext.getBeanNamesForType(filterClass);
            if (beanNames.length == 0) {
                serverEndpointFilter = createInstance();
                if (filterProcessingUrl != null) {
                    serverEndpointFilter.setFilterProcessesUrl(filterProcessingUrl);
                }
            } else {
                serverEndpointFilter = applicationContext.getBean(filterClass);
            }
            http.setSharedObject(filterClass, serverEndpointFilter);
            http.addFilterAfter(serverEndpointFilter, SessionManagementFilter.class);
        }

        public AbstractServerEndpointConfig<F> processingUrl(String processingUrl) {
            this.filterProcessingUrl = processingUrl;
            return this;
        }

        public FidoServerConfigurer<H> and() {
            return FidoServerConfigurer.this;
        }

        protected abstract F createInstance();
    }
}
