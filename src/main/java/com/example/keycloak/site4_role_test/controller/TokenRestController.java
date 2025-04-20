package com.example.keycloak.site4_role_test.controller;

import com.example.keycloak.site4_role_test.util.KeycloakUtil;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class TokenRestController {

    @Autowired
    OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String jwtIssuerUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @PostMapping("/get-token")
    public ResponseEntity<Map> getToken(@AuthenticationPrincipal OidcUser oidcUser, Authentication authentication) {
        Map result = new HashMap();

        try {
            String userId = (String) oidcUser.getUserInfo().getClaims().get("preferred_username");
            String userName = (String) oidcUser.getUserInfo().getClaims().get("name");

            //
            OAuth2AuthorizedClient auth2AuthorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient(((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId(), authentication.getName());
            OAuth2AccessToken oAuth2AccessToken = auth2AuthorizedClient.getAccessToken();
            OAuth2RefreshToken oAuth2RefreshToken = auth2AuthorizedClient.getRefreshToken();

            String idToken = oidcUser.getIdToken().getTokenValue();
            String accessToken = oAuth2AccessToken.getTokenValue();
            String refreshToken = oAuth2RefreshToken.getTokenValue();
            //RPToken get...
            String tokenEndpoint = jwtIssuerUri + "/protocol/openid-connect/token";
            List<Map<String,String>> rpToken = KeycloakUtil.getRPToken(tokenEndpoint, clientId, accessToken);
            //
            JSONArray rpTokenArr = new JSONArray();
            if( rpToken != null ) {
                for(Map<String,String> perm : rpToken) {
                    JSONObject  obj = new JSONObject(perm);
                    rpTokenArr.add(obj);
                }
            }
            //
            result.put("result", "OK");
            result.put("msg", "SUCCESS");
            result.put("userId", userId);
            result.put("userName", userName);
            result.put("id_token", idToken);
            result.put("access_token", accessToken);
            result.put("refresh_token", refreshToken);
            result.put("rp_token", rpTokenArr);
        } catch (Exception e) {
            result.put("result", "NOT_OK");
            System.out.println(e.getMessage());
        }

        return new ResponseEntity<>(result, HttpStatus.OK);
    }

//    private String getRefreshToken(Authentication authentication) {
//        OidcUser oidcUser = (OidcUser)  authentication.getPrincipal();
//        String clientRegistrationId = "keycloak";
//        OAuth2AuthorizedClient client = oAuth2AuthorizedClientService.loadAuthorizedClient(clientRegistrationId, oidcUser.getName());
//
//        if( client != null) {
//            return client.getRefreshToken().getTokenValue();
//        }
//
//        return null;
//    }

    @PostMapping(value = "/protocol/openid-connect/token/inspect")
    public ResponseEntity<Map> getInspect(Authentication authentication) {
        System.out.println("getInspect().......");

        Map result = new HashMap();
        try {
            // Get tokens
            OAuth2AuthorizedClient auth2AuthorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient(((OAuth2AuthenticationToken)authentication).getAuthorizedClientRegistrationId(), authentication.getName());
            OAuth2AccessToken oAuth2AccessToken = auth2AuthorizedClient.getAccessToken();
            String accessToken = oAuth2AccessToken.getTokenValue();
            System.out.println("accessToken=" + accessToken);

            //
            String inspectEndpoint = jwtIssuerUri + "/protocol/openid-connect/token/introspect";
            Map<String, String> inspectResult = KeycloakUtil.getInspect(inspectEndpoint, clientId, clientSecret, accessToken);
            System.out.println("inspectResult=" + inspectResult);

            result.put("result", "OK");
            result.put("data", inspectResult);
        } catch (Exception e) {
            result.put("result", "NOT_OK");
            System.out.println(e.getMessage());
        }

        return new ResponseEntity<>(result, HttpStatus.OK);
    }
}
