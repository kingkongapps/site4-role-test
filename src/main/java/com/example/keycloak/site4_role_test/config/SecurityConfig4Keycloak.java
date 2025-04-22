package com.example.keycloak.site4_role_test.config;

import com.example.keycloak.site4_role_test.util.KeycloakUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig4Keycloak {

    @Autowired
    private KeycloakLogoutHandler keycloakLogoutHandler;
    @Autowired
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
    @Autowired
    private RedisTemplate redisTemplate;

    @Autowired
    private RestTemplate restTemplate;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String jwtIssuerUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

//    public SecurityConfig4Keycloak(KeycloakLogoutHandler logoutHandler,
//                                   OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
//                                   RptService rptService,
//                                   RedisTemplate redisTemplate ) {
//        this.keycloakLogoutHandler = logoutHandler;
//        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
//        this.rptService = rptService;
//        this.redisTemplate = redisTemplate;
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        //
        http
                .csrf(csrf -> csrf.disable())
                // /public/** 경로는 인증 없이 접근 가능하도록 설정
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/img/**", "/js/**", "/css/**", "/fonts/**").permitAll()
                        .requestMatchers("/", "/index.html").permitAll()
                        .requestMatchers("/error/**").permitAll()
                        .requestMatchers("/protocol/**").permitAll()
                        .requestMatchers("/login/**").permitAll()
                        .requestMatchers("/get-token").permitAll()
                        .anyRequest().authenticated()
                )
                // OAuth2 로그인 처리 (Keycloak 로그인 페이지로 리다이렉션)
                .oauth2Login(Customizer.withDefaults())
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(successHandler())
                        .userInfoEndpoint(userInfo -> userInfo.userAuthoritiesMapper(this.customUserAuthoritiesMapper()))
                        .userInfoEndpoint(userInfo -> userInfo.userService(this.customOAuth2UserService()))
                )
                // 리소스 서버로서 JWT 토큰 검증
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(keycloakLogoutHandler)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                );

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return (((request, response, authentication) -> {
            System.out.println("LOGIN_SUCCESS............");

            // Get tokens
            OAuth2AuthorizedClient auth2AuthorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient(((OAuth2AuthenticationToken)authentication).getAuthorizedClientRegistrationId(), authentication.getName());
            OAuth2AccessToken oAuth2AccessToken = auth2AuthorizedClient.getAccessToken();
            OAuth2RefreshToken oAuth2RefreshToken = auth2AuthorizedClient.getRefreshToken();
            String accessToken = oAuth2AccessToken.getTokenValue();
            String refreshToken = oAuth2RefreshToken.getTokenValue();

            // Get username
            String username = "";
            Object principal = authentication.getPrincipal();
            if (principal instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) principal;
                username = oidcUser.getPreferredUsername(); // 바로 사용 가능
            }

            // Check RPToken in redis...
            List<Map<String,String>> rpToken = getRPTokenAndCaching(username, accessToken);

            // Set-Cookie
            String rpTokenStr = (rpToken != null ? rpToken.toString() : "");
            setCookie(response, username, accessToken, refreshToken, rpTokenStr);

            response.sendRedirect("/");
        }));
    }

    private List<Map<String,String>> getRPTokenAndCaching(String username, String accessToken) {
        String redisKey = "rpt:" + username;

        System.out.println("  ===>> RPToken Request (LOGIN_SUCCESS).....................");
        System.out.println("  ===>> RPToken Request (LOGIN_SUCCESS).....................");
        System.out.println("  ===>> RPToken Request (LOGIN_SUCCESS).....................");

        //RPT request...
        System.out.println("------------------[ keycloakUtil.getRPToken ]----------------------");
        String tokenEndpoint = jwtIssuerUri + "/protocol/openid-connect/token";
        List<Map<String,String>> rpToken = KeycloakUtil.getRPToken(tokenEndpoint, clientId, accessToken);
        System.out.println("------------------[ keycloakUtil.getRPToken ]----------------------");
        System.out.println("username=" + username);
        //
        if( rpToken != null ) {
            System.out.println("rpToken==" + rpToken.toString());
            try {
                redisTemplate.opsForValue().set(redisKey, rpToken, Duration.ofMinutes(5));
            } catch (Exception e) {
                System.out.println("REDIS_WRITE_FAIL=" + e.getMessage());
            }
        }

        return rpToken;
    }

    private void setCookie(HttpServletResponse response, String username, String accessToken, String refreshToken, String rpToken) {
        Cookie cookieAccessToken = new Cookie("access_token", accessToken);
        Cookie cookieRefreshToken = new Cookie("refresh_token", refreshToken);
        Cookie cookieRPToken = new Cookie("rp_token", rpToken);
        Cookie cookieUserId = new Cookie("userId", username);
        cookieAccessToken.setMaxAge(180); // 180 sec = 3min...
        cookieAccessToken.setPath("/");
//        cookieAccessToken.setHttpOnly(true);
        cookieRefreshToken.setMaxAge(180); // 180 sec = 3min...
        cookieRefreshToken.setPath("/");
        cookieRefreshToken.setHttpOnly(true);
        cookieRPToken.setMaxAge(180); // 180 sec = 3min...
        cookieRPToken.setPath("/");
        cookieRPToken.setHttpOnly(true);
        cookieUserId.setMaxAge(180); // 180 sec = 3min...
        cookieUserId.setPath("/");
        cookieUserId.setHttpOnly(true);

        response.addCookie(cookieAccessToken);
        response.addCookie(cookieRefreshToken);
//        response.addCookie(cookieRPToken);
        response.addCookie(cookieUserId);
    }

    private GrantedAuthoritiesMapper customUserAuthoritiesMapper() {
        return authorities -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            for(GrantedAuthority authority : authorities ) {
                //ROLE_
                if( authority.getAuthority().startsWith("ROLE_")) {
                    mappedAuthorities.add(authority);
                } else {
                    mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_"+ authority.getAuthority()));
                }
            }
            return mappedAuthorities;
        };
    }

    public OAuth2UserService<OAuth2UserRequest, OAuth2User> customOAuth2UserService() {
        return userRequest -> {
            DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
            OAuth2User oAuth2User = delegate.loadUser(userRequest);
            Map<String,Object> attributes = oAuth2User.getAttributes();
            List<GrantedAuthority> authorities = new ArrayList<>();
            //
            String clientId = userRequest.getClientRegistration().getClientId();
            Map<String,Object> resourceAccess = (Map<String,Object>) attributes.get("resource_access");

            if( resourceAccess != null && resourceAccess.get(clientId) instanceof List ) {
                List<String> roles = (List<String>) resourceAccess.get("roles");
                for(String role : roles) {
                    System.out.println("role=" + role.toUpperCase());
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                }
            }
            return new DefaultOAuth2User(authorities, attributes, "preferred_username");
        };
    }
}