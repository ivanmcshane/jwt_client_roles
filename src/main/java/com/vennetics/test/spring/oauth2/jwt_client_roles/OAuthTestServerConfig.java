package com.vennetics.test.spring.oauth2.jwt_client_roles;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
public class OAuthTestServerConfig {

    private static final String JWT_SIGNING_KEY = "MakeMeConfigurable";

    @EnableResourceServer
    @Configuration
    protected static class ResourceServer extends ResourceServerConfigurerAdapter {

        @Autowired
        private OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

        @Autowired
        private ResourceServerTokenServices jwtTokenServices;

        @Override
        public void configure(final ResourceServerSecurityConfigurer resources) {

            resources.stateless(false)
                     .tokenServices(jwtTokenServices)
                     .authenticationEntryPoint(oauthAuthenticationEntryPoint);

        }

        @Override
        public void configure(final HttpSecurity http) throws Exception {

            http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                .requestMatchers()
                .antMatchers("/test/**")
                .and()
                .anonymous()
                .disable()
                .authorizeRequests()
                .accessDecisionManager(accessDecisionManager())
                .antMatchers("/test/client_and_user_protected")
                .access("#oauth2.clientHasRole('ROLE_CLIENT') and hasAuthority('ROLE_USER')")
                .antMatchers("/test/user_only_protected")
                .access("hasAuthority('ROLE_USER')");
        }

        @Bean
        AccessDecisionManager accessDecisionManager() {

            final OAuth2WebSecurityExpressionHandler expressionHandler = new OAuth2WebSecurityExpressionHandler();
            final WebExpressionVoter expressionVoter = new WebExpressionVoter();
            expressionVoter.setExpressionHandler(expressionHandler);

            final List<AccessDecisionVoter<?>> voters = new ArrayList<>();
            voters.add(expressionVoter);
            voters.add(new AuthenticatedVoter());
            final AccessDecisionManager result = new UnanimousBased(voters);

            return result;

        }
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthorizationServerTokenServices jwtTokenServices;

        @Autowired
        private UserApprovalHandler userApprovalHandler;

        @Autowired
        private ClientDetailsService clientDetailsService;

        @Override
        public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {

            clients.withClientDetails(clientDetailsService);
        }

        @Override
        public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenServices(jwtTokenServices).userApprovalHandler(userApprovalHandler);
        }
    }

    @EnableWebSecurity
    @Configuration
    @Order(4)
    protected static class UserAuthentication extends WebSecurityConfigurerAdapter {

        @Autowired
        private TokenStore tokenStore;

        @Autowired
        private UserApprovalHandler userApprovalHandler;

        @Override
        protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication().withUser("authUser").password("password").roles("USER");
        }

        @Override
        protected void configure(final HttpSecurity http) throws Exception {
            http.antMatcher("/oauth/authorize")
                .authorizeRequests()
                .antMatchers("/oauth/authorize")
                .hasAuthority("ROLE_USER")
                .and()
                .httpBasic()
                .and()
                .csrf()
                .disable();
        }
    }

    @EnableWebMvc
    protected static class TestWebAppContext extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(final DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }
    }

    @Controller
    protected static class TestController {

        @RequestMapping(
                        value = "/test/client_and_user_protected",
                        method = RequestMethod.GET,
                        produces = MediaType.APPLICATION_JSON_VALUE)
        @ResponseBody
        public String userAndClient() {
            return "SUCCESS";
        }

        @RequestMapping(
                        value = "/test/user_only_protected",
                        method = RequestMethod.GET,
                        produces = MediaType.APPLICATION_JSON_VALUE)
        @ResponseBody
        public String userOnly() {
            return "SUCCESS";
        }
    }

    @Bean
    JwtAccessTokenConverter jwtAccessTokenConverter() {

        final JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey(JWT_SIGNING_KEY);
        return jwtAccessTokenConverter;
    }

    @Bean
    JwtTokenStore jwtTokenStore() {

        final JwtTokenStore store = new JwtTokenStore(jwtAccessTokenConverter());

        return store;
    }

    @Bean
    ClientDetailsService clientDetailsService() {
        return new ClientDetailsService() {

            @Override
            public ClientDetails loadClientByClientId(final String clientId) throws ClientRegistrationException {

                // System.out.println("Loading " + clientId);
                final BaseClientDetails result = new BaseClientDetails(clientId,
                                                                       null,
                                                                       "read",
                                                                       "authorization_code",
                                                                       "ROLE_CLIENT");
                result.setClientSecret("secret");
                result.setAutoApproveScopes(Arrays.asList("true"));

                // System.out.println("Returning " + result);
                return result;
            }

        };
    }

    @Bean
    UserApprovalHandler userApprovalHandler() {
        final TokenStoreUserApprovalHandler result = new TokenStoreUserApprovalHandler();
        result.setTokenStore(jwtTokenStore());
        result.setClientDetailsService(clientDetailsService());
        result.setRequestFactory(defaultOauth2RequestFactory());
        return result;
    }

    @Bean
    OAuth2RequestFactory defaultOauth2RequestFactory() {
        final DefaultOAuth2RequestFactory result = new DefaultOAuth2RequestFactory(clientDetailsService());
        result.setCheckUserScopes(false);
        return result;
    }

    @Bean
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {

        final OAuth2AuthenticationEntryPoint result = new OAuth2AuthenticationEntryPoint();

        return result;
    }

    @Bean
    @Primary
    DefaultTokenServices jwtTokenServices() {

        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();

        defaultTokenServices.setTokenStore(jwtTokenStore());
        defaultTokenServices.setClientDetailsService(clientDetailsService());
        defaultTokenServices.setTokenEnhancer(tokenEnhancerChain());
        defaultTokenServices.setSupportRefreshToken(true);

        return defaultTokenServices;
    }

    @Bean
    TokenEnhancerChain tokenEnhancerChain() {
        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter()));
        return tokenEnhancerChain;
    }
}
