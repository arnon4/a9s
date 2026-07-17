const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const listRolesMod = @import("list/roles.zig");
const listRolesImpl = listRolesMod.listRoles;

pub const ListRolesOptions = listRolesMod.Options;
pub const ListRolesResult = listRolesMod.Result;
pub const IamRole = listRolesMod.Role;

const listPoliciesMod = @import("list/policies.zig");
const listPoliciesImpl = listPoliciesMod.listPolicies;

pub const ListPoliciesOptions = listPoliciesMod.Options;
pub const ListPoliciesParams = listPoliciesMod.Params;
pub const ListPoliciesResult = listPoliciesMod.Result;
pub const PolicyScope = listPoliciesMod.Scope;
pub const PolicyUsageFilter = listPoliciesMod.PolicyUsageFilter;
pub const IamPolicy = listPoliciesMod.Policy;

const listAttachedRolePoliciesMod = @import("list/attached_role_policies.zig");
const listAttachedRolePoliciesImpl = listAttachedRolePoliciesMod.listAttachedRolePolicies;

pub const ListAttachedRolePoliciesOptions = listAttachedRolePoliciesMod.Options;
pub const ListAttachedRolePoliciesResult = listAttachedRolePoliciesMod.Result;
pub const AttachedPolicy = listAttachedRolePoliciesMod.AttachedPolicy;

const getRoleMod = @import("get/role.zig");
const getRoleImpl = getRoleMod.getRole;

pub const GetRoleOptions = getRoleMod.Options;
pub const GetRoleResult = getRoleMod.GetRoleResult;
pub const extractTrustedEntities = getRoleMod.extractTrustedEntities;

const getPolicyMod = @import("get/policy.zig");
const getPolicyImpl = getPolicyMod.getPolicy;

pub const GetPolicyOptions = getPolicyMod.Options;
pub const GetPolicyResult = getPolicyMod.GetPolicyResult;

const getPolicyVersionMod = @import("get/policy_version.zig");
const getPolicyVersionImpl = getPolicyVersionMod.getPolicyVersion;

pub const GetPolicyVersionOptions = getPolicyVersionMod.Options;
pub const GetPolicyVersionResult = getPolicyVersionMod.GetPolicyVersionResult;

const listUsersMod = @import("list/users.zig");
const listUsersImpl = listUsersMod.listUsers;

pub const ListUsersOptions = listUsersMod.Options;
pub const ListUsersResult = listUsersMod.Result;
pub const IamUser = listUsersMod.User;

const getUserMod = @import("get/user.zig");
const getUserImpl = getUserMod.getUser;

pub const GetUserOptions = getUserMod.Options;
pub const GetUserResult = getUserMod.GetUserResult;

const listUserPoliciesMod = @import("list/user_policies.zig");
const listUserPoliciesImpl = listUserPoliciesMod.listUserPolicies;

pub const ListUserPoliciesOptions = listUserPoliciesMod.Options;
pub const ListUserPoliciesResult = listUserPoliciesMod.Result;

const getUserPolicyMod = @import("get/user_policy.zig");
const getUserPolicyImpl = getUserPolicyMod.getUserPolicy;

pub const GetUserPolicyOptions = getUserPolicyMod.Options;
pub const GetUserPolicyResult = getUserPolicyMod.GetUserPolicyResult;

const listAttachedUserPoliciesMod = @import("list/attached_user_policies.zig");
const listAttachedUserPoliciesImpl = listAttachedUserPoliciesMod.listAttachedUserPolicies;

pub const ListAttachedUserPoliciesOptions = listAttachedUserPoliciesMod.Options;
pub const ListAttachedUserPoliciesResult = listAttachedUserPoliciesMod.Result;
pub const AttachedUserPolicy = listAttachedUserPoliciesMod.AttachedPolicy;

const listGroupsForUserMod = @import("list/groups_for_user.zig");
const listGroupsForUserImpl = listGroupsForUserMod.listGroupsForUser;

pub const ListGroupsForUserOptions = listGroupsForUserMod.Options;
pub const ListGroupsForUserResult = listGroupsForUserMod.Result;

const listGroupsMod = @import("list/groups.zig");
const listGroupsImpl = listGroupsMod.listGroups;

pub const ListGroupsOptions = listGroupsMod.Options;
pub const ListGroupsParams = listGroupsMod.Params;
pub const ListGroupsResult = listGroupsMod.Result;
pub const IamGroup = listGroupsMod.Group;

const listGroupPoliciesMod = @import("list/group_policies.zig");
const listGroupPoliciesImpl = listGroupPoliciesMod.listGroupPolicies;

pub const ListGroupPoliciesOptions = listGroupPoliciesMod.Options;
pub const ListGroupPoliciesResult = listGroupPoliciesMod.Result;

const listAttachedGroupPoliciesMod = @import("list/attached_group_policies.zig");
const listAttachedGroupPoliciesImpl = listAttachedGroupPoliciesMod.listAttachedGroupPolicies;

pub const ListAttachedGroupPoliciesOptions = listAttachedGroupPoliciesMod.Options;
pub const ListAttachedGroupPoliciesResult = listAttachedGroupPoliciesMod.Result;
pub const AttachedGroupPolicy = listAttachedGroupPoliciesMod.AttachedPolicy;

const getGroupMod = @import("get/group.zig");
const getGroupImpl = getGroupMod.getGroup;

pub const GetGroupOptions = getGroupMod.Options;
pub const GetGroupResult = getGroupMod.GetGroupResult;
pub const IamGroupMember = getGroupMod.GroupMember;

const getGroupPolicyMod = @import("get/group_policy.zig");
const getGroupPolicyImpl = getGroupPolicyMod.getGroupPolicy;

pub const GetGroupPolicyOptions = getGroupPolicyMod.Options;
pub const GetGroupPolicyResult = getGroupPolicyMod.GetGroupPolicyResult;

const listAccessKeysMod = @import("list/access_keys.zig");
const listAccessKeysImpl = listAccessKeysMod.listAccessKeys;

pub const ListAccessKeysOptions = listAccessKeysMod.Options;
pub const ListAccessKeysResult = listAccessKeysMod.Result;
pub const AccessKeyMetadata = listAccessKeysMod.AccessKeyMetadata;

const getAccessKeyLastUsedMod = @import("get/access_key_last_used.zig");
const getAccessKeyLastUsedImpl = getAccessKeyLastUsedMod.getAccessKeyLastUsed;

pub const GetAccessKeyLastUsedOptions = getAccessKeyLastUsedMod.Options;
pub const GetAccessKeyLastUsedResult = getAccessKeyLastUsedMod.GetAccessKeyLastUsedResult;

const generateCredentialReportMod = @import("generate/credential_report.zig");
const generateCredentialReportImpl = generateCredentialReportMod.generateCredentialReport;

pub const GenerateCredentialReportResult = generateCredentialReportMod.GenerateCredentialReportResult;
pub const CredentialReportState = generateCredentialReportMod.ReportState;

const getCredentialReportMod = @import("get/credential_report.zig");
const getCredentialReportImpl = getCredentialReportMod.getCredentialReport;

pub const GetCredentialReportResult = getCredentialReportMod.GetCredentialReportResult;

pub const credential_report = @import("credential_report.zig");

const listOpenIDConnectProvidersMod = @import("list/open_id_connect_providers.zig");
const listOpenIDConnectProvidersImpl = listOpenIDConnectProvidersMod.listOpenIDConnectProviders;

pub const ListOpenIDConnectProvidersOptions = listOpenIDConnectProvidersMod.Options;
pub const ListOpenIDConnectProvidersResult = listOpenIDConnectProvidersMod.Result;
pub const OpenIDConnectProvider = listOpenIDConnectProvidersMod.OpenIDConnectProvider;

const listSAMLProvidersMod = @import("list/saml_providers.zig");
const listSAMLProvidersImpl = listSAMLProvidersMod.listSAMLProviders;

pub const ListSAMLProvidersOptions = listSAMLProvidersMod.Options;
pub const ListSAMLProvidersResult = listSAMLProvidersMod.Result;
pub const SAMLProvider = listSAMLProvidersMod.SAMLProvider;

const getOpenIDConnectProviderMod = @import("get/open_id_connect_provider.zig");
const getOpenIDConnectProviderImpl = getOpenIDConnectProviderMod.getOpenIDConnectProvider;

pub const GetOpenIDConnectProviderOptions = getOpenIDConnectProviderMod.Options;
pub const GetOpenIDConnectProviderResult = getOpenIDConnectProviderMod.GetOpenIDConnectProviderResult;

const getSAMLProviderMod = @import("get/saml_provider.zig");
const getSAMLProviderImpl = getSAMLProviderMod.getSAMLProvider;

pub const GetSAMLProviderOptions = getSAMLProviderMod.Options;
pub const GetSAMLProviderResult = getSAMLProviderMod.GetSAMLProviderResult;
pub const SAMLPrivateKey = getSAMLProviderMod.SAMLPrivateKey;

pub const ClientOptions = struct {
    /// IAM is a global service; signing region should be "us-east-1".
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    /// Override the IAM endpoint (e.g. for LocalStack).
    endpoint_url: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    /// Owned. Base URL with trailing slash.
    endpoint: []const u8,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try allocator.dupe(u8, "https://iam.amazonaws.com/");

        return .{
            .allocator = allocator,
            .io = options.io,
            .region = options.region,
            .credentials = options.credentials,
            .endpoint = endpoint,
        };
    }

    pub fn deinit(self: *Client) void {
        self.allocator.free(self.endpoint);
    }

    /// List IAM roles. Caller owns the result and must call deinit.
    pub fn listRoles(self: *Client, options: ListRolesOptions) !ListRolesResult {
        return listRolesImpl(self, options);
    }

    /// List IAM managed policies. Caller owns the result and must call deinit.
    pub fn listPolicies(self: *Client, options: ListPoliciesOptions) !ListPoliciesResult {
        return listPoliciesImpl(self, options);
    }

    /// List managed policies attached to an IAM role. Caller owns the result and must call deinit.
    pub fn listAttachedRolePolicies(self: *Client, options: ListAttachedRolePoliciesOptions) !ListAttachedRolePoliciesResult {
        return listAttachedRolePoliciesImpl(self, options);
    }

    /// Get full details for a single IAM role. Caller owns the result and must call deinit.
    pub fn getRole(self: *Client, options: GetRoleOptions) !GetRoleResult {
        return getRoleImpl(self, options);
    }

    /// Get full details for a single IAM managed policy. Caller owns the result and must call deinit.
    pub fn getPolicy(self: *Client, options: GetPolicyOptions) !GetPolicyResult {
        return getPolicyImpl(self, options);
    }

    /// Get a specific policy version's document. Caller owns the result and must call deinit.
    pub fn getPolicyVersion(self: *Client, options: GetPolicyVersionOptions) !GetPolicyVersionResult {
        return getPolicyVersionImpl(self, options);
    }

    /// List IAM users. Caller owns the result and must call deinit.
    pub fn listUsers(self: *Client, options: ListUsersOptions) !ListUsersResult {
        return listUsersImpl(self, options);
    }

    /// Get full details for a single IAM user. Caller owns the result and must call deinit.
    pub fn getUser(self: *Client, options: GetUserOptions) !GetUserResult {
        return getUserImpl(self, options);
    }

    /// List the names of inline policies embedded in an IAM user. Caller owns the result and must call deinit.
    pub fn listUserPolicies(self: *Client, options: ListUserPoliciesOptions) !ListUserPoliciesResult {
        return listUserPoliciesImpl(self, options);
    }

    /// Get the document for a single inline policy on an IAM user. Caller owns the result and must call deinit.
    pub fn getUserPolicy(self: *Client, options: GetUserPolicyOptions) !GetUserPolicyResult {
        return getUserPolicyImpl(self, options);
    }

    /// List managed policies attached to an IAM user. Caller owns the result and must call deinit.
    pub fn listAttachedUserPolicies(self: *Client, options: ListAttachedUserPoliciesOptions) !ListAttachedUserPoliciesResult {
        return listAttachedUserPoliciesImpl(self, options);
    }

    /// List the IAM groups an IAM user belongs to. Caller owns the result and must call deinit.
    pub fn listGroupsForUser(self: *Client, options: ListGroupsForUserOptions) !ListGroupsForUserResult {
        return listGroupsForUserImpl(self, options);
    }

    /// List IAM groups. Caller owns the result and must call deinit.
    pub fn listGroups(self: *Client, options: ListGroupsOptions) !ListGroupsResult {
        return listGroupsImpl(self, options);
    }

    /// List the names of inline policies embedded in an IAM group. Caller owns the result and must call deinit.
    pub fn listGroupPolicies(self: *Client, options: ListGroupPoliciesOptions) !ListGroupPoliciesResult {
        return listGroupPoliciesImpl(self, options);
    }

    /// List managed policies attached to an IAM group. Caller owns the result and must call deinit.
    pub fn listAttachedGroupPolicies(self: *Client, options: ListAttachedGroupPoliciesOptions) !ListAttachedGroupPoliciesResult {
        return listAttachedGroupPoliciesImpl(self, options);
    }

    /// Get full details (and member users) for a single IAM group. Caller owns the result and must call deinit.
    pub fn getGroup(self: *Client, options: GetGroupOptions) !GetGroupResult {
        return getGroupImpl(self, options);
    }

    /// Get the document for a single inline policy on an IAM group. Caller owns the result and must call deinit.
    pub fn getGroupPolicy(self: *Client, options: GetGroupPolicyOptions) !GetGroupPolicyResult {
        return getGroupPolicyImpl(self, options);
    }

    /// List access keys for an IAM user. Caller owns the result and must call deinit.
    pub fn listAccessKeys(self: *Client, options: ListAccessKeysOptions) !ListAccessKeysResult {
        return listAccessKeysImpl(self, options);
    }

    /// Get last-used info for a single access key. Caller owns the result and must call deinit.
    pub fn getAccessKeyLastUsed(self: *Client, options: GetAccessKeyLastUsedOptions) !GetAccessKeyLastUsedResult {
        return getAccessKeyLastUsedImpl(self, options);
    }

    /// Start async generation of the account's IAM credential report. Caller owns the result and must call deinit.
    pub fn generateCredentialReport(self: *Client) !GenerateCredentialReportResult {
        return generateCredentialReportImpl(self);
    }

    /// Fetch the generated IAM credential report (call generateCredentialReport first and poll
    /// until its state is .COMPLETE). Caller owns the result and must call deinit.
    pub fn getCredentialReport(self: *Client) !GetCredentialReportResult {
        return getCredentialReportImpl(self);
    }

    /// List IAM OpenID Connect (OIDC) identity providers. Caller owns the result and must call deinit.
    pub fn listOpenIDConnectProviders(self: *Client, options: ListOpenIDConnectProvidersOptions) !ListOpenIDConnectProvidersResult {
        return listOpenIDConnectProvidersImpl(self, options);
    }

    /// List IAM SAML identity providers. Caller owns the result and must call deinit.
    pub fn listSAMLProviders(self: *Client, options: ListSAMLProvidersOptions) !ListSAMLProvidersResult {
        return listSAMLProvidersImpl(self, options);
    }

    /// Get full details for a single IAM OIDC identity provider. Caller owns the result and must call deinit.
    pub fn getOpenIDConnectProvider(self: *Client, options: GetOpenIDConnectProviderOptions) !GetOpenIDConnectProviderResult {
        return getOpenIDConnectProviderImpl(self, options);
    }

    /// Get full details for a single IAM SAML identity provider. Caller owns the result and must call deinit.
    pub fn getSAMLProvider(self: *Client, options: GetSAMLProviderOptions) !GetSAMLProviderResult {
        return getSAMLProviderImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init default endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("https://iam.amazonaws.com/", c.endpoint);
    try std.testing.expectEqualStrings("us-east-1", c.region);
}

test "Client init custom endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
        .endpoint_url = "http://localhost:4566/",
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("http://localhost:4566/", c.endpoint);
}

test {
    _ = @import("list/roles.zig");
    _ = @import("get/role.zig");
    _ = @import("list/policies.zig");
    _ = @import("list/attached_role_policies.zig");
    _ = @import("get/policy.zig");
    _ = @import("get/policy_version.zig");
    _ = @import("list/users.zig");
    _ = @import("get/user.zig");
    _ = @import("list/user_policies.zig");
    _ = @import("get/user_policy.zig");
    _ = @import("list/attached_user_policies.zig");
    _ = @import("list/groups_for_user.zig");
    _ = @import("list/groups.zig");
    _ = @import("list/group_policies.zig");
    _ = @import("list/attached_group_policies.zig");
    _ = @import("get/group.zig");
    _ = @import("get/group_policy.zig");
    _ = @import("list/access_keys.zig");
    _ = @import("get/access_key_last_used.zig");
    _ = @import("generate/credential_report.zig");
    _ = @import("get/credential_report.zig");
    _ = @import("credential_report.zig");
    _ = @import("list/open_id_connect_providers.zig");
    _ = @import("list/saml_providers.zig");
    _ = @import("get/open_id_connect_provider.zig");
    _ = @import("get/saml_provider.zig");
}
