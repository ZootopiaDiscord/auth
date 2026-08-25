package com.zootopiadiscord.keycloak.discord;

import java.io.IOException;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;

/**
 * Maps the roles a user holds in one Discord guild onto Keycloak realm roles or groups.
 *
 * <p>Calls {@code GET /users/@me/guilds/{guild.id}/member} with the user's access token, which needs
 * the {@code guilds.members.read} scope. Discord returns role ids, not names, so {@link #ROLE_MAP}
 * translates each id to a realm role name or group path.
 *
 * <p>Full sync: names in {@link #ROLE_MAP} are granted or revoked to match Discord, anything else is
 * left alone, and missing roles or groups are skipped with a warning. Any Discord failure — a 404
 * for a non-member included — aborts the login. Needs sync mode {@code FORCE} to run on every login.
 */
public class DiscordGuildRolesMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "discord-guild-roles-idp-mapper";

    static final String GUILD_ID = "guildId";
    static final String TARGET = "target";
    static final String ROLE_MAP = "roleMap";

    static final String TARGET_REALM_ROLES = "Realm roles";
    static final String TARGET_GROUPS = "Groups";

    static final String MEMBER_URL = "https://discord.com/api/v10/users/@me/guilds/%s/member";

    private static final Logger LOG = Logger.getLogger(DiscordGuildRolesMapper.class);

    private static final String[] COMPATIBLE_PROVIDERS = {OIDCIdentityProviderFactory.PROVIDER_ID};

    /** Only the modes the mapper actually implements; LEGACY would only ever revoke. */
    private static final Set<IdentityProviderSyncMode> SYNC_MODES =
            EnumSet.of(IdentityProviderSyncMode.IMPORT, IdentityProviderSyncMode.FORCE);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = buildConfigProperties();

    private static List<ProviderConfigProperty> buildConfigProperties() {
        ProviderConfigProperty guildId = new ProviderConfigProperty();
        guildId.setName(GUILD_ID);
        guildId.setLabel("Guild ID");
        guildId.setType(ProviderConfigProperty.STRING_TYPE);
        guildId.setHelpText("ID of the Discord guild (server) to read the user's roles from.");

        ProviderConfigProperty target = new ProviderConfigProperty();
        target.setName(TARGET);
        target.setLabel("Map to");
        target.setType(ProviderConfigProperty.LIST_TYPE);
        target.setOptions(List.of(TARGET_REALM_ROLES, TARGET_GROUPS));
        target.setDefaultValue(TARGET_REALM_ROLES);
        target.setHelpText("Whether the Discord roles are mapped onto Keycloak realm roles or onto groups.");

        ProviderConfigProperty roleMap = new ProviderConfigProperty();
        roleMap.setName(ROLE_MAP);
        roleMap.setLabel("Role mapping");
        roleMap.setType(ProviderConfigProperty.MAP_TYPE);
        roleMap.setHelpText("Maps a Discord role ID to the name of the realm role, or the path of the group, "
                + "to grant while the user holds it. A Discord role ID may be listed more than once to grant "
                + "several roles or groups.");

        return List.of(guildId, target, roleMap);
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        sync(session, realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        sync(session, realm, user, mapperModel, context);
    }

    /**
     * Grants every configured role or group the user still holds in Discord, and revokes the rest.
     */
    private static void sync(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String guildId = trimmed(mapperModel.getConfig().get(GUILD_ID));
        Map<String, List<String>> roleMap = mapperModel.getConfigMap(ROLE_MAP);
        if (guildId == null || roleMap.isEmpty()) {
            if (guildId == null && roleMap.isEmpty()) {
                LOG.debugf("Mapper '%s' is not configured; not touching any roles.", mapperModel.getName());
            } else {
                LOG.warnf("Mapper '%s' is missing its %s; not touching any roles.", mapperModel.getName(),
                        guildId == null ? "guild ID" : "role mapping");
            }
            return;
        }

        Set<String> discordRoleIds = fetchGuildRoleIds(session, accessToken(context), guildId);

        Set<String> configured = new LinkedHashSet<>();
        Set<String> held = new HashSet<>();
        roleMap.forEach((discordRoleId, names) -> {
            configured.addAll(names);
            if (discordRoleIds.contains(discordRoleId)) {
                held.addAll(names);
            }
        });

        boolean toGroups = TARGET_GROUPS.equals(mapperModel.getConfig().get(TARGET));
        for (String name : configured) {
            if (toGroups) {
                applyGroup(session, realm, user, mapperModel, name, held.contains(name));
            } else {
                applyRealmRole(realm, user, mapperModel, name, held.contains(name));
            }
        }
    }

    private static void applyRealmRole(RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, String roleName, boolean shouldHold) {
        RoleModel role = realm.getRole(roleName);
        if (role == null) {
            LOG.warnf("Mapper '%s' references realm role '%s', which does not exist in realm '%s'; skipping it.",
                    mapperModel.getName(), roleName, realm.getName());
            return;
        }

        if (shouldHold) {
            user.grantRole(role);
        } else {
            user.deleteRoleMapping(role);
        }
    }

    private static void applyGroup(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, String groupPath, boolean shouldHold) {
        GroupModel group = KeycloakModelUtils.findGroupByPath(session, realm, groupPath);
        if (group == null) {
            LOG.warnf("Mapper '%s' references group '%s', which does not exist in realm '%s'; skipping it.",
                    mapperModel.getName(), groupPath, realm.getName());
            return;
        }

        if (shouldHold) {
            user.joinGroup(group);
        } else {
            user.leaveGroup(group);
        }
    }

    /**
     * Reads the ids of the roles the user holds in the guild.
     *
     * @throws IdentityBrokerException if Discord is unreachable or answers with anything but 200,
     *                                 including the 404 for a non-member.
     */
    static Set<String> fetchGuildRoleIds(KeycloakSession session, String accessToken, String guildId) {
        String url = MEMBER_URL.formatted(guildId);
        try (SimpleHttpResponse response = SimpleHttp.create(session)
                .doGet(url)
                .auth(accessToken)
                .acceptJson()
                .asResponse()) {

            if (response.getStatus() != 200) {
                throw new IdentityBrokerException("Discord returned status " + response.getStatus()
                        + " for guild " + guildId + "; cannot determine the user's roles.");
            }

            Set<String> roleIds = new HashSet<>();
            JsonNode roles = response.asJson().get("roles");
            if (roles != null) {
                roles.forEach(role -> roleIds.add(role.asText()));
            }
            return roleIds;
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not read the user's roles in Discord guild " + guildId + ".", e);
        }
    }

    /** OIDC providers set the token response, never the bare FEDERATED_ACCESS_TOKEN key. */
    private static String accessToken(BrokeredIdentityContext context) {
        Object response = context.getContextData().get(OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE);
        String accessToken = response instanceof AccessTokenResponse tokenResponse ? tokenResponse.getToken() : null;

        if (accessToken == null || accessToken.isBlank()) {
            throw new IdentityBrokerException("No Discord access token on the brokered login; cannot read guild roles.");
        }
        return accessToken;
    }

    private static String trimmed(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS.clone();
    }

    @Override
    public String getDisplayCategory() {
        return "Role Importer";
    }

    @Override
    public String getDisplayType() {
        return "Discord Guild Roles";
    }

    @Override
    public String getHelpText() {
        return "Grants Keycloak realm roles or groups based on the roles the user holds in a Discord guild. "
                + "Requires the 'guilds.members.read' scope on the identity provider.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
