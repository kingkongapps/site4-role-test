package com.example.keycloak.site4_role_test.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class KeycloakLogoutHandler implements LogoutHandler {

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String KEYCLOAK_URL = "";
    @Value("${appl.url}")
    private String APPL_URL = "";

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        System.out.println("KeycloakLogoutHander::logout()...........1");
        // Spring session delete...
        if( authentication !=null && authentication.getDetails() != null ) {
            System.out.println("KeycloakLogoutHander::logout()...........2");
            request.getSession().invalidate();
            SecurityContextHolder.clearContext();
            System.out.println("KeycloakLogoutHander::logout()...........3");

            //
            try {
                String keycloakLogoutUrl = this.KEYCLOAK_URL + "/protocol/openid-connect/logout?post_logout_redirect_uri=" + this.APPL_URL + "/&id_token_hint=" + getIdToken(authentication);
                System.out.println("keycloakLogoutUrl=" + keycloakLogoutUrl);
                System.out.println("KEYCLOAK_URL=" + this.KEYCLOAK_URL);
                System.out.println("APPL_URL=====" + this.APPL_URL);

                response.sendRedirect(keycloakLogoutUrl);
                System.out.println("KeycloakLogoutHander::logout()...........4");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private String getIdToken(Authentication authentication) {
        if( authentication instanceof OAuth2AuthenticationToken ) {
            OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            return oidcUser.getIdToken().getTokenValue();
        }
        return null;
    }
}
