package com.example.keycloak.site4_role_test.service;//package com.example.keycloak.site1_auth.service;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.HttpEntity;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.MediaType;
//import org.springframework.stereotype.Service;
//import org.springframework.util.LinkedMultiValueMap;
//import org.springframework.util.MultiValueMap;
//import org.springframework.web.client.RestTemplate;
//
//import java.util.Map;
//
//@Service
//public class RptService {
//
//    @Autowired
//    RestTemplate restTemplate;
//
//    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
//    private String jwtIssuerUri;
//
//    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
//    private String clientId;
//
//    public String getRPT(String accessToken) {
//        System.out.println("jwtIssuerUri=" + jwtIssuerUri);
//        System.out.println("clientId=====" + clientId);
//        //
//        HttpHeaders headers = new HttpHeaders();
//        headers.setBearerAuth(accessToken);
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//
//        //
//        MultiValueMap<String,String> params = new LinkedMultiValueMap<>();
//        params.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
//        params.add("audience", clientId);
//        // 아래 response_mode 까지 넘기면.. permission 키만 복호화되서 평문으로 리턴...
//        // 안넘기면 Token이 리턴... -> 일단 Token 으로 받고 Token expire 까지 체크하도록 구현한다.
////        params.add("response_mode", "permissions");
//
//        //
//        HttpEntity<MultiValueMap<String,String>> entity = new HttpEntity<>(params, headers);
//
//        String tokenEndpoint = jwtIssuerUri + "/protocol/openid-connect/token";
//        System.out.println("tokenEndpoint=" + tokenEndpoint);
//        //
//        HttpEntity<Map> response   = restTemplate.exchange(tokenEndpoint, HttpMethod.POST, entity, Map.class);
//        Map temp = response.getBody();
//        String rptToken = (String) temp.get("access_token");
////        String rptToken = response.getBody().toString();
//        System.out.println("rptToken=" + rptToken);
//        return rptToken;
//
////        // params.add("response_mode", "permissions");; 까지 넘기면... 응답은 list로 넘어 옴...
////        HttpEntity<Object> response2 = null;
////        try {
////            response2 = restTemplate.exchange( tokenEndpoint, HttpMethod.POST, entity, Object.class);
////            String rptToken = response2.getBody().toString();
////            System.out.println("rptToken=" + rptToken);
////            //
////            List<LinkedHashMap> list = (List<LinkedHashMap>) response2.getBody();
////            for(Map map : list ) {
////                System.out.println(map.toString());
////            }
////            return response2.getBody().toString();
////        } catch (Exception e) {
////            System.out.println("RPT_error_msg=" + e.getMessage());
////            e.printStackTrace();
////        }
////        return null;
//    }
//}
