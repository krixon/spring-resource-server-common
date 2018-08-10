package com.krixon.resourceserver.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.FixedAuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.FixedPrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OAuth2UserInfoTokenServices implements ResourceServerTokenServices
{
    private final Log logger = LogFactory.getLog(getClass());

    private final String userInfoEndpointUrl;

    private final String clientId;

    private OAuth2RestOperations restTemplate;

    private AuthoritiesExtractor authoritiesExtractor = new FixedAuthoritiesExtractor();

    private PrincipalExtractor principalExtractor = new FixedPrincipalExtractor();

    public OAuth2UserInfoTokenServices(String userInfoEndpointUrl, String clientId)
    {
        this.userInfoEndpointUrl = userInfoEndpointUrl;
        this.clientId = clientId;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken)
    throws AuthenticationException, InvalidTokenException
    {
        Map<String, Object> map = getMap(this.userInfoEndpointUrl, accessToken);

        if (map.containsKey("error")) {
            this.logger.debug("userinfo returned error: " + map.get("error"));
            throw new InvalidTokenException(accessToken);
        }

        return extractAuthentication(map);
    }

    private OAuth2Authentication extractAuthentication(Map<String, Object> map)
    {
        Object principal = getPrincipal(map);
        OAuth2Request request = getRequest(map);
        List<GrantedAuthority> authorities = this.authoritiesExtractor.extractAuthorities(map);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal, "N/A", authorities);

        token.setDetails(map);

        return new OAuth2Authentication(request, token);
    }

    private Object getPrincipal(Map<String, Object> map)
    {
        Object principal = this.principalExtractor.extractPrincipal(map);

        return (principal == null ? "unknown" : principal);
    }

    @SuppressWarnings({"unchecked"})
    private OAuth2Request getRequest(Map<String, Object> map)
    {
        Map<String, Object> request = (Map<String, Object>) map.get("oauth2Request");
        String clientId = (String) request.get("clientId");

        Set<String> scope = new LinkedHashSet<>(request.containsKey("scope")
            ? (Collection<String>) request.get("scope")
            : Collections.emptySet());

        return new OAuth2Request(
            null,
            clientId,
            null,
            true,
            new HashSet<>(scope),
            null,
            null,
            null,
            null
        );
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken)
    {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    @SuppressWarnings({"unchecked"})
    private Map<String, Object> getMap(String path, String accessToken)
    {
        this.logger.info("Getting user info from: " + path);

        try {
            OAuth2RestOperations restTemplate = this.restTemplate;

            if (restTemplate == null) {
                BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
                resource.setClientId(this.clientId);
                restTemplate = new OAuth2RestTemplate(resource);
            }

            OAuth2AccessToken existingToken = restTemplate.getOAuth2ClientContext().getAccessToken();

            if (existingToken == null || !accessToken.equals(existingToken.getValue())) {
                DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
                token.setTokenType(DefaultOAuth2AccessToken.BEARER_TYPE);
                restTemplate.getOAuth2ClientContext().setAccessToken(token);
            }

            return restTemplate.getForEntity(path, Map.class).getBody();
        } catch (Exception ex) {
            this.logger.info("Could not fetch user details: " + ex.getClass() + ", " + ex.getMessage());

            return Collections.singletonMap("error", "Could not fetch user details");
        }
    }
}
