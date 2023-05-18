package ch.cristiano.demo.webapp;

import java.io.IOException;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response.Status;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.engine.AuthorizationService;
import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.identity.User;
import org.camunda.bpm.webapp.impl.security.auth.AuthenticationUtil;
import org.camunda.bpm.webapp.impl.security.auth.Authentications;
import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.camunda.bpm.webapp.impl.security.auth.UserAuthentication;
import org.camunda.bpm.engine.authorization.Authorization;
import org.camunda.bpm.engine.authorization.Permissions;
import org.camunda.bpm.engine.authorization.Resource;
import org.camunda.bpm.engine.authorization.Resources;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

public class AadOauth2AuthenticationFilter extends ContainerBasedAuthenticationFilter {

    private static final String CAMUNDA_ROLE_ADMIN = "camunda-admin";
    private static final String CAMUNDA_GROUP_NAME = "Camunda BPM Administrators";
    private static final String CAMUNDA_GROUP_TYPE = "SYSTEM";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;

        String engineName = super.extractEngineName(httpRequest);

        if (engineName == null) {
            chain.doFilter(request, response);
            return;
        }

        ProcessEngine engine = super.getAddressedEngine(engineName);

        if (engine == null) {
            httpResponse.sendError(404, "Process engine " + engineName + " not available");
            return;
        }

        AuthenticationResult authenticationResult = super.authenticationProvider.extractAuthenticatedUser(httpRequest,
                engine);
        if (authenticationResult.isAuthenticated()) {
            Authentications authentications = AuthenticationUtil.getAuthsFromSession(httpRequest.getSession());
            String authenticatedUser = authenticationResult.getAuthenticatedUser();

            if (!super.existisAuthentication(authentications, engineName, authenticatedUser)) {
                List<String> groups = authenticationResult.getGroups();
                List<String> tenants = authenticationResult.getTenants();

                UserAuthentication authentication = createAzureAuthentication(engine, authenticatedUser, groups,
                        tenants);
                authentications.addOrReplace(authentication);
            }

            chain.doFilter(request, response);
        } else {
            httpResponse.setStatus(Status.UNAUTHORIZED.getStatusCode());
            super.authenticationProvider.augmentResponseByAuthenticationChallenge(httpResponse, engine);
        }
    }

    protected UserAuthentication createAzureAuthentication(ProcessEngine processEngine, String username,
            List<String> groups,
            List<String> tenants) {

        UserAuthentication userAuthentication = AuthenticationUtil.createAuthentication(processEngine,
                username,
                groups,
                tenants);
        if (userAuthentication != null) {
            return userAuthentication;
        } else {
            return createCamundaResourcesAndAuthenticate(processEngine, username, groups, tenants);
        }
    }

    private UserAuthentication createCamundaResourcesAndAuthenticate(ProcessEngine processEngine, String username,
            List<String> groups,
            List<String> tenants) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        IdentityService camundaIdentityService = processEngine.getIdentityService();
        AuthorizationService camundaAuthorizationService = processEngine.getAuthorizationService();

        boolean adminGroupAvailable = checkIfAdminGroupAvailable(camundaIdentityService);
        if (!adminGroupAvailable) {
            Group newGroup = camundaIdentityService.newGroup(CAMUNDA_ROLE_ADMIN);
            newGroup.setName(CAMUNDA_GROUP_NAME);
            newGroup.setType(CAMUNDA_GROUP_TYPE);
            camundaIdentityService.saveGroup(newGroup);
            for (Resource resource : Resources.values()) {
                Authorization authorization = camundaAuthorizationService
                        .createNewAuthorization(Authorization.AUTH_TYPE_GRANT);
                authorization.addPermission(Permissions.ALL);
                authorization.setGroupId(CAMUNDA_ROLE_ADMIN);
                authorization.setResource(resource);
                authorization.setResourceId("*");
                authorization.setResourceType(resource.resourceType());
                camundaAuthorizationService.saveAuthorization(authorization);
            }
        }
        User newUser = camundaIdentityService.newUser(username);
        newUser.setFirstName(this.getGivenName(authentication));
        newUser.setLastName(this.getFamilyName(authentication));
        newUser.setEmail(this.getEmail(authentication));
        camundaIdentityService.saveUser(newUser);
        camundaIdentityService.createMembership(username, CAMUNDA_ROLE_ADMIN);
        UserAuthentication newUserAuthentication = AuthenticationUtil.createAuthentication(processEngine,
                username,
                groups,
                tenants);
        return newUserAuthentication;
    }

    private boolean checkIfAdminGroupAvailable(IdentityService identityService) {
        Group camundaAdminGroup = identityService.createGroupQuery().groupId(CAMUNDA_ROLE_ADMIN).singleResult();
        return camundaAdminGroup != null;
    }

    private String getGivenName(Authentication authentication) {
        return this.getUserFromAuthentication(authentication).getAttribute("given_name");
    }

    private String getFamilyName(Authentication authentication) {
        return this.getUserFromAuthentication(authentication).getAttribute("family_name");
    }

    private String getEmail(Authentication authentication) {
        return this.getUserFromAuthentication(authentication).getAttribute("email");
    }

    @SuppressWarnings("unchecked")
    private <T extends OAuth2AuthenticatedPrincipal> T getUserFromAuthentication(Authentication authentication) {
        return (T) authentication.getPrincipal();
    }
}