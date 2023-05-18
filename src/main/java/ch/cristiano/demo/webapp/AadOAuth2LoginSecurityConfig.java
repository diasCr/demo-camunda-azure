package ch.cristiano.demo.webapp;

import java.util.Collections;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.context.request.RequestContextListener;

import com.azure.spring.cloud.autoconfigure.aad.AadResourceServerWebSecurityConfigurerAdapter;
import com.azure.spring.cloud.autoconfigure.aad.AadWebSecurityConfigurerAdapter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AadOAuth2LoginSecurityConfig {

    @Order(1)
    @Configuration
    public static class ApiWebSecurityConfigurationAdapter extends AadResourceServerWebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            // @formatter:off
            http.antMatcher("/engine-rest/**")
                    .authorizeRequests().anyRequest().authenticated();
            // @formatter:on
        }
    }

    @Configuration
    @Order(SecurityProperties.BASIC_AUTH_ORDER - 15)
    public static class HtmlWebSecurityConfigurerAdapter extends AadWebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            // @formatter:off
            http.csrf().disable().authorizeRequests().antMatchers("/camunda/**").authenticated()
                .antMatchers("/**").permitAll();
            // @formatter:on
        }

        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER - 15)
        public FilterRegistrationBean<AadOauth2AuthenticationFilter> containerBasedAuthenticationFilter() {
            FilterRegistrationBean<AadOauth2AuthenticationFilter> filterRegistration = new FilterRegistrationBean<>();
            filterRegistration.setFilter(new AadOauth2AuthenticationFilter());
            filterRegistration.setInitParameters(Collections.singletonMap("authentication-provider",
                    AadOAuth2AuthenticationProvider.class.getName()));
            filterRegistration.setOrder(101);
            filterRegistration.addUrlPatterns("/camunda/*");
            return filterRegistration;
        }

        @Bean
        @Order(0)
        public RequestContextListener requestContextListener() {
            return new RequestContextListener();
        }
    }
}
