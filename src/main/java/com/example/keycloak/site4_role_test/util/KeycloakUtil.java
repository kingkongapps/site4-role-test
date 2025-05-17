package com.example.keycloak.site4_role_test.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class KeycloakUtil {
    public static void main(String[] args) throws Exception {
        String accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJXUmt3a0Nya1RCXzVabW9wNV9wNlVid3dLZ2FuZ3J4Y0RPeThhRVMyLXpFIn0.eyJleHAiOjE3NDQ0MzAwMTAsImlhdCI6MTc0NDQyOTcxMCwiYXV0aF90aW1lIjoxNzQ0NDI5NzEwLCJqdGkiOiIwMjhlMmRmNC04Yzg0LTQ4NzktOGFmZC1iMWUzZDAyYWMxMTMiLCJpc3MiOiJodHRwOi8vMjIwLjcwLjI5LjIwODozMDAwMC9yZWFsbXMvU1NPX1RFU1QiLCJhdWQiOiJzc28tdGVzdC1zaXRlMSIsInN1YiI6ImYxZmU2YzUzLTE3NGEtNDc4Zi05ZTExLTNmYjIxZWJlOTZjNyIsInR5cCI6IklEIiwiYXpwIjoic3NvLXRlc3Qtc2l0ZTEiLCJub25jZSI6IkdEa2JpTXNacFdMNUhvSW9OdnVXRnY0M1lRSmNFVGJJRGRaXzdLUW1MUVUiLCJzaWQiOiJlNWIwNDgyNC1hNjkxLTQwNzAtOWMzZC0zNDE4NjA3ZTU1ZmYiLCJhdF9oYXNoIjoibHlYRTA1NEhqWDZBZG4zd3ZrLVE1ZyIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6InRlc3QxIHVzZXIxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIxIiwiZ2l2ZW5fbmFtZSI6InRlc3QxIiwibG9jYWxlIjoia28iLCJmYW1pbHlfbmFtZSI6InVzZXIxIiwiZW1haWwiOiJrYW5nc2NvbUBuYXZlci5jb20ifQ.vp4DsUKnlrJY_EPRYcg_cQhLrfe_ueW55lsj8n7FT5XbOJO7iJlCmo4dVYlWqZevdYvnRVQPl0sTU9rEfF_hY6IY-IWCQhBSw_mcaEUo8mFEmNtFjbDPHDwoQJKdupkXeo1VlUwpW8y7dGjB5hQvM1Zl-UkUDkz9TGShvBLC9CpUOAF7nY00A-EUNzSN5oGGBPsnZrwZJfTJxzPBHqWLSp50XwsVTqgs4hZlHxhosMpr7xqN1ScBs4DteTIMaVrtgwqc7UTkHZ5jL9DIB0ALP3ORVUH92bg_oDY8Bvq6IaPJP5ck5mbAa3bVTbDL113azXVr4IKJtlFB994HMkJ46g";

        String jwksUrl = "http://220.70.29.208:30000/realms/SSO_TEST/protocol/openid-connect/certs";
        String targetKid = "WRkwkCrkTB_5Zmop5_p6UbwwKgangrxcDOy8aES2-zE";
        PublicKey publicKey = loadPublicKeyFromJwks(jwksUrl, targetKid);

        boolean isTokenExpired = isTokenExpired(accessToken, publicKey);
        System.out.println("isTokenExpired=" + isTokenExpired);
    }


public static List<Map<String,String>> getRPToken(String tokenEndpoint, String clientId, String accessToken) {
    System.out.println("tokenEndpoint=" + tokenEndpoint);
    //
    try(CloseableHttpClient client = HttpClients.createDefault()) {
        HttpPost post = new HttpPost(tokenEndpoint);
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        post.setHeader("Authorization", "Bearer " + accessToken);

        //
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket"));
        params.add(new BasicNameValuePair("audience", clientId));
        params.add(new BasicNameValuePair("response_mode", "permissions"));

        post.setEntity(new UrlEncodedFormEntity(params));

        return client.execute(post, httpResponse -> {
            System.out.println("HTTP_CODE==" + httpResponse.getStatusLine().getStatusCode());
            System.out.println("HTTP_ERROR=" + httpResponse.getStatusLine().getReasonPhrase());
            if( httpResponse.getStatusLine().getStatusCode() == 200 ) {
                ObjectMapper mapper = new ObjectMapper();
                List<Map<String, String>> list = mapper.readValue(httpResponse.getEntity().getContent(), List.class);
                //permission만 문자로 보낼때... 그러나 list 객체로 반환한다...
//                    String permissions = mapper.readValue(httpResponse.getEntity().getContent(), String.class);
                for(Map map : list) {
                    System.out.println("map=" + map.toString());
                }
                return list;
            } else {
                return null;
            }
        });
    } catch (Exception e) {
        System.out.println(e.getMessage());
    }
    return null;
}

    public static String getRPT_restTemplate(RestTemplate restTemplate, String tokenEndpoint, String clientId, String accessToken) {
        System.out.println("tokenEndpoint=" + tokenEndpoint);
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        //
        MultiValueMap<String,String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        params.add("audience", clientId);
        // 아래 response_mode 까지 넘기면.. permission 키만 복호화되서 평문으로 리턴...
        // 안넘기면 Token이 리턴... -> 일단 Token 으로 받고 Token expire 까지 체크하도록 구현한다.
//        params.add("response_mode", "permissions");

        //
        HttpEntity<MultiValueMap<String,String>> entity = new HttpEntity<>(params, headers);

        //
        HttpEntity<Map> response   = restTemplate.exchange(tokenEndpoint, HttpMethod.POST, entity, Map.class);
        Map temp = response.getBody();
        String rptToken = (String) temp.get("access_token");
//        String rptToken = response.getBody().toString();
        System.out.println("rptToken=" + rptToken);
        return rptToken;
    }

    public static String getPrivateKeyId(String accessToken) throws Exception {
        if( accessToken == null ) return null;

        // 1. 토큰을 . 으로 분리 (Header.Payload.Signature)
        String[] parts = accessToken.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("잘못된 JWT 토큰 형식입니다.");
        }
        // 2. Header 부분 Base64 디코딩
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));

        // 3. JSON 파싱 (json-simple 사용)
        JSONParser parser = new JSONParser();
        JSONObject header = (JSONObject) parser.parse(headerJson);

        // 4. kid 추출
        return header.getAsString("kid");
    }

    public static Object getClientRoles(String accessToken, String clientId) throws Exception {
        if( accessToken == null ) return null;

        // 1. 토큰을 . 으로 분리 (Header.Payload.Signature)
        String[] parts = accessToken.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("잘못된 JWT 토큰 형식입니다.");
        }
        // 2. Payload 부분 Base64 디코딩
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));

        // 3. JSON 파싱 (json-simple 사용)
        JSONParser parser = new JSONParser();
        JSONObject payload = (JSONObject) parser.parse(payloadJson);

        // 4. resource_access 추출
        JSONObject resourceAccess = (JSONObject) payload.get("resource_access");

        // 5. client 추출
        JSONObject roles = (JSONObject) resourceAccess.get(clientId);

        // 6. roles 추출
        return roles.get("roles");
    }

    public static boolean isTokenExpired(String rptToken, PublicKey publicKey) {
        System.out.println("JwtUtil::isTokenExpired()::rptToken=" + rptToken);
        boolean isExpired = false;
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(rptToken)
                    .getBody();
            Date expiration = claims.getExpiration();

            System.out.println(new Date());

            isExpired = expiration.before(new Date());
        } catch (Exception e) {
            System.out.println(e.getMessage());
//            e.printStackTrace();
            isExpired = true;
        }
        System.out.println("JwtUtil::isTokenExpired()::isExpired=" + isExpired);
        return isExpired;
    }

    public static PublicKey loadPublicKeyFromJwks(String jwksUrl, String targetKid) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        // 1. JWKS JSON 가져오기
        InputStream inputStream = new URL(jwksUrl).openStream();
        JsonNode jwks = objectMapper.readTree(inputStream);
        JsonNode keys = jwks.get("keys");

        for (JsonNode key : keys) {
            String kid = key.get("kid").asText();
            if (targetKid.equals(kid)) {
                // 2. n (modulus), e (exponent) 추출
                String n = key.get("n").asText();
                String e = key.get("e").asText();

                // 3. Base64url 디코딩 후 BigInteger로 변환
                byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
                byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

                BigInteger modulus = new BigInteger(1, modulusBytes);
                BigInteger exponent = new BigInteger(1, exponentBytes);

                // 4. RSA PublicKey 생성
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(publicKeySpec);
            }
        }

        throw new IllegalArgumentException("해당 kid에 맞는 키를 JWKS에서 찾을 수 없습니다: " + targetKid);
    }

    public static Map<String,String> getInspect(String inspectEndpoint, String clientId, String clientSecret, String accessToken) {
        System.out.println("getInspect().......");

        try(CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost post = new HttpPost(inspectEndpoint);
            String basicAuth = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
            post.setHeader("Authorization", "Basic " + basicAuth);
            post.setHeader("Content-Type", "application/x-www-form-urlencoded");
//            post.setHeader("Authorization", "Bearer " + accessToken); // 로그인 후 accessTokenㅇ로 시도하면 성공...

            List<BasicNameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("token", accessToken));

            //
            post.setEntity(new UrlEncodedFormEntity(params));

            return client.execute(post, httpResponse -> {
                System.out.println("HTTP_CODE=" + httpResponse.getStatusLine().getStatusCode());
                System.out.println("ERROR_MSG=" + httpResponse.getStatusLine().getReasonPhrase());

                if( httpResponse.getStatusLine().getStatusCode() == 200 ) {
                    ObjectMapper mapper = new ObjectMapper();
                    Map<String,String> result = mapper.readValue(httpResponse.getEntity().getContent(), Map.class);
                    return result;
                } else {
                    return null;
                }
            });
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }
}
