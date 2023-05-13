package ch.cristiano.demo.webapp;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.engine.rest.security.auth.impl.ContainerBasedAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import javax.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.stream.Collectors;

public class AadOAuth2AuthenticationProvider extends ContainerBasedAuthenticationProvider {

    private static final String CAMUNDA_ROLE_ADMIN = "camunda-admin";

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            return AuthenticationResult.unsuccessful();
        }

        String authenticatedUsername = prepareUsername(authentication);
        // authentication.getName();
        if (authenticatedUsername == null || authenticatedUsername.isEmpty()) {
            return AuthenticationResult.unsuccessful();
        }

        // RBAC - Role based access control. It neeeds "camunda-admin" role!
        List<String> authenticatedUserRoles = getUserRoles(authentication);
        if (!authenticatedUserRoles.contains(CAMUNDA_ROLE_ADMIN)) {
            return AuthenticationResult.unsuccessful();
        }

        AuthenticationResult authenticationResult = AuthenticationResult.successful(authenticatedUsername);
        authenticationResult.setGroups(authenticatedUserRoles);

        return authenticationResult;
    }

    private List<String> getUserRoles(Authentication authentication) {
        List<String> roles = authentication.getAuthorities().stream()
                .map(res -> res.getAuthority())
                .map(res -> res.substring(8)) // Strip "APPROLE_"
                .collect(Collectors.toList());

        return roles;
    }

    private String prepareUsername(Authentication authentication) {
        String username = null;
        String givenName = this.getUserFromAuthentication(authentication).getAttribute("given_name");
        String familyName = this.getUserFromAuthentication(authentication).getAttribute("family_name");
        username = givenName.replaceAll("\\s+", "") + familyName.replaceAll("\\s+", "");
        return username;
    }

    @SuppressWarnings("unchecked")
    private <T extends OAuth2AuthenticatedPrincipal> T getUserFromAuthentication(Authentication authentication) {
        return (T) authentication.getPrincipal();
    }
}
