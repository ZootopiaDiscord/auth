package com.zootopiadiscord.keycloak.discord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.DefaultDataMarshaller;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.MapperTypeSerializer;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;
import org.mockito.MockedStatic;

class DiscordGuildRolesMapperTest {

    private static final String GUILD = "123456789012345678";
    private static final String MOD_ROLE_ID = "987654321098765432";
    private static final String VIP_ROLE_ID = "876543210987654321";
    private static final String TOKEN = "discord-access-token";

    private final DiscordGuildRolesMapper mapper = new DiscordGuildRolesMapper();

    private final KeycloakSession session = mock(KeycloakSession.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final UserModel user = mock(UserModel.class);

    // --- provider contract ----------------------------------------------------

    /** These strings are what the Ansible task writes; renaming one breaks it silently. */
    @Test
    void exposesTheContractAnsibleConfiguresItThrough() {
        assertEquals("discord-guild-roles-idp-mapper", mapper.getId());
        assertEquals(List.of("guildId", "target", "roleMap"),
                mapper.getConfigProperties().stream().map(ProviderConfigProperty::getName).toList());
        assertEquals(DiscordGuildRolesMapper.TARGET_REALM_ROLES, targetProperty().getDefaultValue());
        assertEquals(List.of(DiscordGuildRolesMapper.TARGET_REALM_ROLES, DiscordGuildRolesMapper.TARGET_GROUPS),
                targetProperty().getOptions());
    }

    @Test
    void offersItselfToOidcIdentityProviders() {
        assertEquals(List.of(OIDCIdentityProviderFactory.PROVIDER_ID),
                List.of(mapper.getCompatibleProviders()));
    }

    @Test
    void supportsOnlyImportAndForceSyncModes() {
        assertTrue(mapper.supportsSyncMode(IdentityProviderSyncMode.IMPORT));
        assertTrue(mapper.supportsSyncMode(IdentityProviderSyncMode.FORCE));
        assertFalse(mapper.supportsSyncMode(IdentityProviderSyncMode.LEGACY));
    }

    // --- realm roles ----------------------------------------------------------

    @Test
    void grantsHeldRolesAndRevokesTheRest() {
        RoleModel moderator = mock(RoleModel.class);
        RoleModel vip = mock(RoleModel.class);
        when(realm.getRole("moderator")).thenReturn(moderator);
        when(realm.getRole("vip")).thenReturn(vip);

        updateBrokeredUser(Set.of(VIP_ROLE_ID), roleMapping(Map.of(
                MOD_ROLE_ID, List.of("moderator"),
                VIP_ROLE_ID, List.of("vip"))));

        verify(user).grantRole(vip);
        verify(user).deleteRoleMapping(moderator);
        verify(user, never()).grantRole(moderator);
    }

    @Test
    void grantsRoleWhenAnyOfSeveralDiscordRolesMapsToIt() {
        RoleModel staff = mock(RoleModel.class);
        when(realm.getRole("staff")).thenReturn(staff);

        // The user holds only one of the two Discord roles that grant "staff".
        updateBrokeredUser(Set.of(VIP_ROLE_ID), roleMapping(Map.of(
                MOD_ROLE_ID, List.of("staff"),
                VIP_ROLE_ID, List.of("staff"))));

        verify(user).grantRole(staff);
        verify(user, never()).deleteRoleMapping(staff);
    }

    @Test
    void leavesRolesOutsideTheMappingAlone() {
        RoleModel moderator = mock(RoleModel.class);
        when(realm.getRole("moderator")).thenReturn(moderator);

        updateBrokeredUser(Set.of(MOD_ROLE_ID), roleMapping(Map.of(MOD_ROLE_ID, List.of("moderator"))));

        verify(user).grantRole(moderator);
        verify(user, never()).deleteRoleMapping(any());
        verify(realm, never()).getRole("some-unrelated-role");
    }

    @Test
    void skipsRolesThatDoNotExistInTheRealm() {
        when(realm.getRole("moderator")).thenReturn(null);

        updateBrokeredUser(Set.of(MOD_ROLE_ID), roleMapping(Map.of(MOD_ROLE_ID, List.of("moderator"))));

        verify(user, never()).grantRole(any());
        verify(user, never()).deleteRoleMapping(any());
    }

    /** First broker login goes through importNewUser, not updateBrokeredUser. */
    @Test
    void importNewUserAppliesTheSameMapping() {
        RoleModel moderator = mock(RoleModel.class);
        when(realm.getRole("moderator")).thenReturn(moderator);
        IdentityProviderMapperModel model = mapperModel(roleMapping(Map.of(MOD_ROLE_ID, List.of("moderator"))));

        withDiscordRoles(Set.of(MOD_ROLE_ID),
                () -> mapper.importNewUser(session, realm, user, model, context(TOKEN)));

        verify(user).grantRole(moderator);
    }

    // --- groups ---------------------------------------------------------------

    @Test
    void joinsHeldGroupsAndLeavesTheRest() {
        GroupModel moderators = mock(GroupModel.class);
        GroupModel vips = mock(GroupModel.class);
        Map<String, String> config = groupMapping(Map.of(
                MOD_ROLE_ID, List.of("/moderators"),
                VIP_ROLE_ID, List.of("/vips")));

        try (MockedStatic<KeycloakModelUtils> utils = mockStatic(KeycloakModelUtils.class)) {
            utils.when(() -> KeycloakModelUtils.findGroupByPath(session, realm, "/moderators")).thenReturn(moderators);
            utils.when(() -> KeycloakModelUtils.findGroupByPath(session, realm, "/vips")).thenReturn(vips);

            updateBrokeredUser(Set.of(MOD_ROLE_ID), config);
        }

        verify(user).joinGroup(moderators);
        verify(user).leaveGroup(vips);
    }

    @Test
    void skipsGroupsThatDoNotExistInTheRealm() {
        Map<String, String> config = groupMapping(Map.of(MOD_ROLE_ID, List.of("/moderators")));

        try (MockedStatic<KeycloakModelUtils> utils = mockStatic(KeycloakModelUtils.class)) {
            utils.when(() -> KeycloakModelUtils.findGroupByPath(session, realm, "/moderators")).thenReturn(null);

            updateBrokeredUser(Set.of(MOD_ROLE_ID), config);
        }

        verify(user, never()).joinGroup(any());
        verify(user, never()).leaveGroup(any());
    }

    @Test
    void doesNotTouchRealmRolesWhenTargetingGroups() {
        GroupModel moderators = mock(GroupModel.class);
        Map<String, String> config = groupMapping(Map.of(MOD_ROLE_ID, List.of("/moderators")));

        try (MockedStatic<KeycloakModelUtils> utils = mockStatic(KeycloakModelUtils.class)) {
            utils.when(() -> KeycloakModelUtils.findGroupByPath(session, realm, "/moderators")).thenReturn(moderators);

            updateBrokeredUser(Set.of(MOD_ROLE_ID), config);
        }

        verify(user).joinGroup(moderators);
        verify(user, never()).grantRole(any());
        verify(user, never()).deleteRoleMapping(any());
    }

    // --- incomplete configuration ---------------------------------------------

    @Test
    void doesNothingAndDoesNotCallDiscordWhenUnconfigured() {
        assertNoDiscordCallAndNoChanges(new HashMap<>());
    }

    @Test
    void doesNothingAndDoesNotCallDiscordWhenTheGuildIdIsBlank() {
        Map<String, String> config = roleMapping(Map.of(MOD_ROLE_ID, List.of("moderator")));
        config.put(DiscordGuildRolesMapper.GUILD_ID, "  ");

        assertNoDiscordCallAndNoChanges(config);
    }

    @Test
    void doesNothingAndDoesNotCallDiscordWhenTheRoleMappingIsEmpty() {
        Map<String, String> config = roleMapping(Map.of());

        assertNoDiscordCallAndNoChanges(config);
    }

    @Test
    void trimsTheConfiguredGuildId() {
        RoleModel moderator = mock(RoleModel.class);
        when(realm.getRole("moderator")).thenReturn(moderator);
        Map<String, String> config = roleMapping(Map.of(MOD_ROLE_ID, List.of("moderator")));
        config.put(DiscordGuildRolesMapper.GUILD_ID, "  " + GUILD + "  ");

        // Only the trimmed URL is stubbed, so an untrimmed id would not reach Discord.
        updateBrokeredUser(Set.of(MOD_ROLE_ID), config);

        verify(user).grantRole(moderator);
    }

    // --- access token ---------------------------------------------------------

    @Test
    void failsLoginWhenNoDiscordAccessTokenIsAvailable() {
        IdentityProviderMapperModel model = mapperModel(roleMapping(Map.of(MOD_ROLE_ID, List.of("moderator"))));

        assertThrows(IdentityBrokerException.class,
                () -> mapper.updateBrokeredUser(session, realm, user, model, context(null)));
    }

    /**
     * OIDCIdentityProvider never sets the bare FEDERATED_ACCESS_TOKEN key that plain OAuth2
     * providers use. Reading it instead of the token response failed every login.
     */
    @Test
    void doesNotRelyOnTheBareFederatedAccessTokenKey() {
        RoleModel moderator = mock(RoleModel.class);
        when(realm.getRole("moderator")).thenReturn(moderator);

        BrokeredIdentityContext context = mock(BrokeredIdentityContext.class);
        when(context.getContextData()).thenReturn(new HashMap<>(
                Map.of(UserAuthenticationIdentityProvider.FEDERATED_ACCESS_TOKEN, TOKEN)));
        IdentityProviderMapperModel model = mapperModel(roleMapping(Map.of(MOD_ROLE_ID, List.of("moderator"))));

        // Discord answers successfully here: the mapper must fail before the call, not because of it.
        withDiscordRoles(Set.of(MOD_ROLE_ID), () -> assertThrows(IdentityBrokerException.class,
                () -> mapper.updateBrokeredUser(session, realm, user, model, context)));

        verify(user, never()).grantRole(moderator);
    }

    /**
     * Pins a Keycloak assumption: first broker login rebuilds the context from the authentication
     * session, round-tripping every context data value through this marshaller.
     */
    @Test
    void keycloakMarshallerRoundTripsTheTokenResponse() {
        DefaultDataMarshaller marshaller = new DefaultDataMarshaller();

        String serialized = marshaller.serialize(tokenResponse(TOKEN));
        AccessTokenResponse restored = marshaller.deserialize(serialized, AccessTokenResponse.class);

        assertEquals(TOKEN, restored.getToken());
    }

    // --- Discord call ---------------------------------------------------------

    @Test
    void readsRoleIdsFromTheMemberResponse() throws IOException {
        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            stubDiscordResponse(http, discordResponse(200, rolesBody(Set.of(MOD_ROLE_ID, VIP_ROLE_ID))));

            assertEquals(Set.of(MOD_ROLE_ID, VIP_ROLE_ID),
                    DiscordGuildRolesMapper.fetchGuildRoleIds(session, TOKEN, GUILD));
        }
    }

    /** A member with no roles beyond @everyone. */
    @Test
    void treatsAMemberResponseWithoutRolesAsHoldingNone() throws IOException {
        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            stubDiscordResponse(http, discordResponse(200, "{\"user\":{\"id\":\"1\"}}"));

            assertEquals(Set.of(), DiscordGuildRolesMapper.fetchGuildRoleIds(session, TOKEN, GUILD));
        }
    }

    @Test
    void closesTheDiscordResponse() throws IOException {
        SimpleHttpResponse response = discordResponse(200, rolesBody(Set.of(MOD_ROLE_ID)));

        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            stubDiscordResponse(http, response);
            DiscordGuildRolesMapper.fetchGuildRoleIds(session, TOKEN, GUILD);
        }

        verify(response).close();
    }

    @Test
    void failsLoginWhenTheUserIsNotAMemberOfTheGuild() throws IOException {
        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            stubDiscordResponse(http, discordResponse(404, "{}"));

            assertThrows(IdentityBrokerException.class,
                    () -> DiscordGuildRolesMapper.fetchGuildRoleIds(session, TOKEN, GUILD));
        }
    }

    /** What Discord answers when guilds.members.read was never granted. */
    @Test
    void failsLoginWhenDiscordRejectsTheToken() throws IOException {
        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            stubDiscordResponse(http, discordResponse(401, "{\"message\":\"401: Unauthorized\"}"));

            assertThrows(IdentityBrokerException.class,
                    () -> DiscordGuildRolesMapper.fetchGuildRoleIds(session, TOKEN, GUILD));
        }
    }

    @Test
    void failsLoginWhenDiscordIsUnreachable() throws IOException {
        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            when(stubDiscordRequest(http).asResponse()).thenThrow(new IOException("connection refused"));

            assertThrows(IdentityBrokerException.class,
                    () -> DiscordGuildRolesMapper.fetchGuildRoleIds(session, TOKEN, GUILD));
        }
    }

    // --- helpers --------------------------------------------------------------

    /** Runs updateBrokeredUser with Discord reporting exactly {@code discordRoleIds}. */
    private void updateBrokeredUser(Set<String> discordRoleIds, Map<String, String> config) {
        IdentityProviderMapperModel model = mapperModel(config);
        withDiscordRoles(discordRoleIds,
                () -> mapper.updateBrokeredUser(session, realm, user, model, context(TOKEN)));
    }

    /** Runs {@code action} with the member endpoint stubbed to report {@code discordRoleIds}. */
    private void withDiscordRoles(Set<String> discordRoleIds, Runnable action) {
        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            stubDiscordResponse(http, discordResponse(200, rolesBody(discordRoleIds)));
            action.run();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    private void assertNoDiscordCallAndNoChanges(Map<String, String> config) {
        try (MockedStatic<SimpleHttp> http = mockStatic(SimpleHttp.class)) {
            mapper.updateBrokeredUser(session, realm, user, mapperModel(config), context(TOKEN));
            http.verifyNoInteractions();
        }

        verify(user, never()).grantRole(any());
        verify(user, never()).deleteRoleMapping(any());
        verify(user, never()).joinGroup(any());
        verify(user, never()).leaveGroup(any());
    }

    /** Stubs the exact call the mapper is expected to make. */
    private SimpleHttpRequest stubDiscordRequest(MockedStatic<SimpleHttp> http) {
        SimpleHttp simpleHttp = mock(SimpleHttp.class);
        SimpleHttpRequest request = mock(SimpleHttpRequest.class);
        http.when(() -> SimpleHttp.create(session)).thenReturn(simpleHttp);
        when(simpleHttp.doGet(DiscordGuildRolesMapper.MEMBER_URL.formatted(GUILD))).thenReturn(request);
        when(request.auth(TOKEN)).thenReturn(request);
        when(request.acceptJson()).thenReturn(request);
        return request;
    }

    private void stubDiscordResponse(MockedStatic<SimpleHttp> http, SimpleHttpResponse response) throws IOException {
        when(stubDiscordRequest(http).asResponse()).thenReturn(response);
    }

    private static SimpleHttpResponse discordResponse(int status, String body) throws IOException {
        JsonNode json = new ObjectMapper().readTree(body);
        SimpleHttpResponse response = mock(SimpleHttpResponse.class);
        when(response.getStatus()).thenReturn(status);
        when(response.asJson()).thenReturn(json);
        return response;
    }

    private static String rolesBody(Set<String> roleIds) {
        return "{\"roles\":[" + roleIds.stream()
                .map(id -> "\"" + id + "\"")
                .collect(Collectors.joining(",")) + "]}";
    }

    /** Config for the test guild, targeting realm roles. */
    private static Map<String, String> roleMapping(Map<String, List<String>> mapping) {
        Map<String, String> config = new HashMap<>();
        config.put(DiscordGuildRolesMapper.GUILD_ID, GUILD);
        config.put(DiscordGuildRolesMapper.ROLE_MAP, MapperTypeSerializer.serialize(mapping));
        return config;
    }

    /** The same, targeting groups; values are group paths. */
    private static Map<String, String> groupMapping(Map<String, List<String>> mapping) {
        Map<String, String> config = roleMapping(mapping);
        config.put(DiscordGuildRolesMapper.TARGET, DiscordGuildRolesMapper.TARGET_GROUPS);
        return config;
    }

    private static IdentityProviderMapperModel mapperModel(Map<String, String> config) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("discord-guild-roles");
        model.setConfig(config);
        return model;
    }

    private static BrokeredIdentityContext context(String accessToken) {
        BrokeredIdentityContext context = mock(BrokeredIdentityContext.class);
        Map<String, Object> data = new HashMap<>();
        if (accessToken != null) {
            data.put(OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse(accessToken));
        }
        when(context.getContextData()).thenReturn(data);
        return context;
    }

    private static AccessTokenResponse tokenResponse(String accessToken) {
        AccessTokenResponse response = new AccessTokenResponse();
        response.setToken(accessToken);
        return response;
    }

    private ProviderConfigProperty targetProperty() {
        return mapper.getConfigProperties().stream()
                .filter(property -> DiscordGuildRolesMapper.TARGET.equals(property.getName()))
                .findFirst()
                .orElseThrow();
    }
}
