package com.vennetics.test.spring.oauth2.jwt_client_roles;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = { OAuthTestServerConfig.class })
public class OAuthTestServerConfigTest {

    private static final boolean ENABLE_LOGS = false;
    static {
        if (ENABLE_LOGS) {
            // Get the root logger
            final Logger rootLogger = Logger.getLogger("");
            for (final Handler handler : rootLogger.getHandlers()) {
                // Change log level of default handler(s) of root logger
                // The paranoid would check that this is the ConsoleHandler ;)
                handler.setLevel(Level.FINEST);
            }
            // Set root logger level
            rootLogger.setLevel(Level.FINE);
        }
    }

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private Filter springSecurityFilterChain;

    private MockMvc mvc;

    @Before
    public void test() {

        mvc = MockMvcBuilders.webAppContextSetup(context)

        .addFilters(springSecurityFilterChain).build();
    }

    @Test
    public void testUserOnlySequence() throws Exception {

        final MvcResult authoriseResult = mvc.perform(get("/oauth/authorize?client_id=client&response_type=code&scope=read&redirect_uri=http://127.0.0.1:8080/test").with(httpBasic("authUser",
                                                                                                                                                                                    "password")))
                                             .andExpect(status().isFound())
                                             .andReturn();

        // Get the code
        final String code = StringUtils.substringAfter(authoriseResult.getResponse()
                                                                      .getRedirectedUrl(), "=");

        final MvcResult getTokenResult = mvc.perform(post("/oauth/token?grant_type=authorization_code&redirect_uri=http://127.0.0.1:8080/test&code="
                        + code).with(httpBasic("client", "secret")))
                                            .andReturn();

        // Get the access token
        final JSONObject jsonObject = new JSONObject(getTokenResult.getResponse()
                                                                   .getContentAsString());

        final String accessToken = jsonObject.getString("access_token");

        // Invoke resource server

        mvc.perform(get("/test/user_only_protected").header("Authorization",
                                                            "Bearer " + accessToken))
           .andExpect(status().isOk())
           .andReturn();

    }

    @Test
    public void testUserAndClientSequence() throws Exception {

        final MvcResult authoriseResult = mvc.perform(get("/oauth/authorize?client_id=client&response_type=code&scope=read&redirect_uri=http://127.0.0.1:8080/test").with(httpBasic("authUser",
                                                                                                                                                                                    "password")))
                                             .andExpect(status().isFound())
                                             .andReturn();

        // Get the code
        final String code = StringUtils.substringAfter(authoriseResult.getResponse()
                                                                      .getRedirectedUrl(), "=");

        final MvcResult getTokenResult = mvc.perform(post("/oauth/token?grant_type=authorization_code&redirect_uri=http://127.0.0.1:8080/test&code="
                        + code).with(httpBasic("client", "secret")))
                                            .andReturn();

        // Get the access token
        final JSONObject jsonObject = new JSONObject(getTokenResult.getResponse()
                                                                   .getContentAsString());

        final String accessToken = jsonObject.getString("access_token");

        // Invoke resource server

        mvc.perform(get("/test/client_and_user_protected").header("Authorization",
                                                                  "Bearer " + accessToken))
           .andExpect(status().isOk())
           .andReturn();

    }

}
