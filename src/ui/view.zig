const std = @import("std");

const terminal = @import("../terminal/terminal.zig");
const Coord = terminal.Coord;
const fetcher = @import("../sdk/credentials/fetcher.zig");
const ProfileSet = @import("../app/profile_set.zig").ProfileSet;

const S3BucketsView = @import("../app/views/s3/buckets.zig").S3BucketsView;
const S3ObjectsView = @import("../app/views/s3/objects.zig").S3ObjectsView;
const S3ObjectView = @import("../app/views/s3/object.zig").S3ObjectView;
const S3ObjectContentView = @import("../app/views/s3/object_content.zig").S3ObjectContentView;
const S3DownloadView = @import("../app/views/s3/download.zig");
const BaseView = @import("../app/views/base.zig");
const SSOProfileView = @import("../app/views/auth/sso_profile.zig");
const CredentialsView = @import("../app/views/auth/credentials.zig");
const AuthPromptView = @import("../app/views/auth/prompt.zig");
const MessageView = @import("message.zig");
const ConfirmView = @import("confirm.zig");
const HelpView = @import("../app/views/help.zig").HelpView;
const LambdasView = @import("../app/views/lambda/lambdas.zig");
const LambdaView = @import("../app/views/lambda/lambda.zig").LambdaView;
const LambdaContentView = @import("../app/views/lambda/lambda_content.zig").LambdaContentView;
const LogGroupsView = @import("../app/views/logs/log_groups.zig");
const LogStreamsView = @import("../app/views/logs/log_streams.zig");
const LogEventsView = @import("../app/views/logs/log_events.zig").LogEventsView;
const IamHomeView = @import("../app/views/iam/iam_home.zig");
const IamRolesView = @import("../app/views/iam/roles.zig");
const IamPoliciesView = @import("../app/views/iam/policies.zig");
const IamRoleView = @import("../app/views/iam/role.zig");
const IamRolePoliciesView = @import("../app/views/iam/role_policies.zig");
const IamRoleTrustPolicyView = @import("../app/views/iam/trust_policy.zig");
const IamPolicyView = @import("../app/views/iam/policy.zig");
const IamPolicyDocumentView = @import("../app/views/iam/policy_document.zig");
const IamUsersView = @import("../app/views/iam/users.zig");
const IamUserView = @import("../app/views/iam/user.zig");
const IamUserInlinePoliciesView = @import("../app/views/iam/user_inline_policies.zig");
const IamUserInlinePolicyDocumentView = @import("../app/views/iam/user_inline_policy_document.zig");
const IamGroupsView = @import("../app/views/iam/groups.zig");
const IamGroupView = @import("../app/views/iam/group.zig");
const IamGroupInlinePoliciesView = @import("../app/views/iam/group_inline_policies.zig");
const IamGroupInlinePolicyDocumentView = @import("../app/views/iam/group_inline_policy_document.zig");
const IamIdentityProvidersView = @import("../app/views/iam/identity_providers.zig");
const IamOidcProviderView = @import("../app/views/iam/oidc_provider.zig");
const IamSamlProviderView = @import("../app/views/iam/saml_provider.zig");
const SecretsView = @import("../app/views/secretsmanager/secrets.zig");
const SecretView = @import("../app/views/secretsmanager/secret.zig");
const SecretValueView = @import("../app/views/secretsmanager/secret_value.zig");
const ResourcePolicyView = @import("../app/views/secretsmanager/resource_policy.zig");

const Event = @import("../event.zig").Event;

pub const ViewContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: *fetcher.CredentialsStore,
    /// Primary region (first in regions list). Used by S3 and single-region views.
    region: []const u8,
    /// All active regions. Multi-region views (e.g. Lambda) iterate this.
    regions: []const []const u8,
    color_support: terminal.ColorSupport,
    search_text: ?[]const u8 = null,
    account_id: ?[]const u8 = null,
    profile_set: *ProfileSet,
};

/// Tagged union over all concrete view types. Dispatches rendering and input to the active variant.
pub const View = union(enum) {
    base: BaseView,
    s3_buckets: S3BucketsView,
    s3_objects: S3ObjectsView,
    s3_object: S3ObjectView,
    s3_object_content: S3ObjectContentView,
    s3_download: S3DownloadView,
    sso_profile: SSOProfileView,
    manual_credentials: CredentialsView,
    auth_prompt: AuthPromptView,
    message: MessageView,
    confirm: ConfirmView,
    help: HelpView,
    lambda_functions: LambdasView,
    lambda_function: LambdaView,
    lambda_function_content: LambdaContentView,
    logs_log_groups: LogGroupsView,
    logs_log_streams: LogStreamsView,
    logs_log_events: LogEventsView,
    iam_home: IamHomeView,
    iam_roles: IamRolesView,
    iam_policies: IamPoliciesView,
    iam_role: IamRoleView,
    iam_role_policies: IamRolePoliciesView,
    iam_role_trust_policy: IamRoleTrustPolicyView,
    iam_policy: IamPolicyView,
    iam_policy_document: IamPolicyDocumentView,
    iam_users: IamUsersView,
    iam_user: IamUserView,
    iam_user_inline_policies: IamUserInlinePoliciesView,
    iam_user_inline_policy_document: IamUserInlinePolicyDocumentView,
    iam_groups: IamGroupsView,
    iam_group: IamGroupView,
    iam_group_inline_policies: IamGroupInlinePoliciesView,
    iam_group_inline_policy_document: IamGroupInlinePolicyDocumentView,
    iam_identity_providers: IamIdentityProvidersView,
    iam_oidc_provider: IamOidcProviderView,
    iam_saml_provider: IamSamlProviderView,
    secretsmanager_secrets: SecretsView,
    secretsmanager_secret: SecretView,
    secretsmanager_secret_value: SecretValueView,
    secretsmanager_resource_policy: ResourcePolicyView,

    const Self = @This();

    pub fn handleEvent(self: *Self, event: Event, ctx: ViewContext) !Action {
        return switch (self.*) {
            inline else => |*v| v.handleEvent(event, ctx),
        };
    }

    pub fn render(self: *Self, writer: *std.Io.Writer, size: Coord) !void {
        return switch (self.*) {
            inline else => |*v| v.render(writer, size),
        };
    }

    pub fn name(self: *Self) []const u8 {
        switch (self.*) {
            inline else => |*v| return v.breadcrumb(),
        }
    }

    pub fn fgColor(self: *Self) []const u8 {
        return switch (self.*) {
            inline else => |*v| v.fg_color,
        };
    }

    pub fn bgColor(self: *Self) []const u8 {
        return switch (self.*) {
            .message => |*v| v.fg_color,
            inline else => |*v| v.bg_color,
        };
    }

    pub fn deinit(self: *Self) void {
        switch (self.*) {
            inline else => |*v| v.deinit(),
        }
    }

    /// Returns true for views that own a text input field and should receive raw key events.
    /// When true, the app will not intercept ':' or '/' for the command bar.
    pub fn wantsRawInput(self: *Self) bool {
        return switch (self.*) {
            .manual_credentials => true,
            else => false,
        };
    }
};

/// Navigation action returned by a view's event handler, consumed by the app's view stack.
pub const Action = union(enum) {
    none,
    quit,
    push: View,
    pop,
    command: Command,
};

/// Commands available via pressing colon (':')
pub const Command = enum {
    login,
};
