package com.example.keycloak.site4_role_test.config;

import com.example.keycloak.site4_role_test.util.KeycloakUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.springframework.web.util.WebUtils.getCookie;

@Component
public class KeycloakAuthorizationInterceptor implements HandlerInterceptor {
    @Autowired
    OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @Autowired
    RedisTemplate redisTemplate;

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String jwtIssuerUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object object) throws Exception {
        String resource = request.getRequestURI();
        String contentType = request.getContentType();

        //
        if( "/".equals(resource) ) return true;
        if( resource.startsWith("/home")) return true;
        if( resource.startsWith("/error")) return true;
        if( resource.startsWith("/protocol")) return true;
        if( resource.startsWith("/login/profile")) return true;
        if( resource.startsWith("/get-token")) return true;

        //
        if( contentType != null ) {
            if( contentType.startsWith("/image/")) return true;
        }
        if( resource.indexOf(".css") >= 0 ||
            resource.indexOf(".js")  >= 0 ||
            resource.indexOf(".ico") >= 0 ||
            resource.indexOf(".font")>= 0 ) return true;

        //
        Cookie accessTokenCookie = getCookie(request, "access_token");
        Cookie userIdCookie = getCookie(request, "userId");

        String accessToken = (accessTokenCookie != null ? accessTokenCookie.getValue() : "");
        String username = (userIdCookie != null ? userIdCookie.getValue() : "");
        String scope = request.getMethod().toUpperCase();

        //
        System.out.println("preHandle()::METHOD(scope)=" + scope);
        System.out.println("preHandle()::resource======" + resource);
        System.out.println("preHandle()::username======" + username);
        System.out.println("preHandle()::accessToken===" + accessToken);

        //CURD 중에 GET ==> READ 로
        //         POST/PUT/DELETE ==> WRITE 로 scope을 치환..
        // -> 사유 : scope을 2개만 정의하는 이유는 - 일기 vs (수정/삭제/생성) 2개만 구분해도 충분.. 생성한 사람이 수정도 하고 , 삭제도 하니까...
        scope = "GET".equals(scope) ? "READ" : "WRITE";
        // 1. READ RPToken...
        // 2. Permission Check...
        List<Map<String,String>> rpToken = readRPToken(username, accessToken);
        if( checkPermission(rpToken, resource, scope)) {
            return true;
        } else {
            request.setAttribute("errorMessage", "접근 권한이 없습니다.");
            request.setCharacterEncoding("UTF-8");
            response.setCharacterEncoding("UTF-8");
            response.setContentType("text/html; charset=UTf-8");

            request.getRequestDispatcher("/error/unauthorized").forward(request, response);
            return false;
        }
    }

    private List<Map<String,String>> readRPToken(String username, String accessToken) {
        // Redis cache에서 먼저 읽는다.
        // Redis cache에 없으면 Keycloak 에서 직접 읽는다.
        String redisKey = "rpt:" + username;
        List<Map<String,String>> cachedRptoken = null;
        boolean IS_REDIS_OK = false;

        // STEP-1 :: Redis cache READ...
        try {
            cachedRptoken = (List<Map<String,String>>) redisTemplate.opsForValue().get(redisKey);
            IS_REDIS_OK = true;
        } catch (Exception e) {
            IS_REDIS_OK = false;
            System.out.println(e.getMessage());
        }
        System.out.println("cachedRptoken=" + cachedRptoken);

        //
        if( cachedRptoken == null ) {
            System.out.println("===> Keycloak RPToken Request..........");
            System.out.println("===> Keycloak RPToken Request..........");
            System.out.println("===> Keycloak RPToken Request..........");
            //
            System.out.println("------------------[ keycloakUtil.getRPToken ]----------------------");
            String tokenEndpoint = jwtIssuerUri + "/protocol/openid-connect/token";
            List<Map<String,String>> rptoken = KeycloakUtil.getRPToken(tokenEndpoint, clientId, accessToken);
            System.out.println("------------------[ keycloakUtil.getRPToken ]----------------------");
            System.out.println("username=" + username);

            //
            if( rptoken != null ) {
                cachedRptoken = rptoken;
                System.out.println("rptoken=" + rptoken);
                if( IS_REDIS_OK ) {
                    try {
                        redisTemplate.opsForValue().set(redisKey, rptoken, Duration.ofMinutes(5));
                    } catch (Exception e) {
                        System.out.println("REDIS_WRITE_FAIL=" + e.getMessage());
                    }
                } else {
                    System.out.println("REDIS_IS_OFF.........SKIP..........");
                }
            }

        } else {
            System.out.println("===> RPToken - CACHE READ OK ..........................");
            System.out.println("===> RPToken - CACHE READ OK ..........................");
            System.out.println("===> RPToken - CACHE READ OK ..........................");
        }

        return cachedRptoken;
    }

    private boolean checkPermission(List<Map<String,String>> rpToken, String resource, String scope ) {
        System.out.println("checkPermission()............");
        for(Map<String,String> perm : rpToken) {
            String resourcePattern = perm.get("rsname");
            String regex = resourcePattern.replace("*", ".*");

            //
            System.out.print(" ===> pattern 일치??? [" + resource + "] vs [" + regex + "]");
            if( resource.matches(regex) ) {
                System.out.println(" ===> pattern 일치 (OK)");
                if( "READ".equals(scope) ) {
                    System.out.println(" ===> READ scope 일치..." + scope);
                    return true;
                } else if ("WRITE".equals(scope)) {
                    Object scopes = perm.get("scopes");
                    if( scopes.toString().indexOf(scope)>=0 ) {
                        System.out.println(" ===> WRITE scope 일치 ... " + scopes + " vs " + scope);
                        return true;
                    } else {
                        System.out.println(" ===> WRITE scope 불일치 ... XXXXXXXXXXXXXX");
                        return false;
                    }
                }
            }
            System.out.println(" ===> pattern 불칠치 ... XXXXXXXXXXXXXX");
        }
        return false;
    }
}
