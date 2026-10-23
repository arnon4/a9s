const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const describeVpcsMod = @import("describe/vpcs.zig");
const describeVpcsImpl = describeVpcsMod.describeVpcs;

pub const DescribeVpcsOptions = describeVpcsMod.Options;
pub const DescribeVpcsParams = describeVpcsMod.Params;
pub const DescribeVpcsResult = describeVpcsMod.Result;
pub const Filter = describeVpcsMod.Filter;
pub const Vpc = describeVpcsMod.Vpc;
pub const VpcTag = describeVpcsMod.Tag;
pub const VpcCidrAssociation = describeVpcsMod.CidrAssociation;

const describeVpcAttributeMod = @import("describe/vpc_attribute.zig");
const describeVpcAttributeImpl = describeVpcAttributeMod.describeVpcAttribute;

pub const DescribeVpcAttributeOptions = describeVpcAttributeMod.Options;
pub const DescribeVpcAttributeParams = describeVpcAttributeMod.Params;
pub const DescribeVpcAttributeResult = describeVpcAttributeMod.Result;
pub const VpcAttribute = describeVpcAttributeMod.Attribute;

const describeSubnetsMod = @import("describe/subnets.zig");
const describeSubnetsImpl = describeSubnetsMod.describeSubnets;

pub const DescribeSubnetsOptions = describeSubnetsMod.Options;
pub const DescribeSubnetsParams = describeSubnetsMod.Params;
pub const DescribeSubnetsResult = describeSubnetsMod.Result;
pub const Subnet = describeSubnetsMod.Subnet;

const describeDhcpOptionsMod = @import("describe/dhcp_options.zig");
const describeDhcpOptionsImpl = describeDhcpOptionsMod.describeDhcpOptions;

pub const DescribeDhcpOptionsOptions = describeDhcpOptionsMod.Options;
pub const DescribeDhcpOptionsParams = describeDhcpOptionsMod.Params;
pub const DescribeDhcpOptionsResult = describeDhcpOptionsMod.Result;
pub const DhcpOptions = describeDhcpOptionsMod.DhcpOptions;
pub const DhcpConfiguration = describeDhcpOptionsMod.Configuration;

const describeRouteTablesMod = @import("describe/route_tables.zig");
const describeRouteTablesImpl = describeRouteTablesMod.describeRouteTables;

pub const DescribeRouteTablesOptions = describeRouteTablesMod.Options;
pub const DescribeRouteTablesParams = describeRouteTablesMod.Params;
pub const DescribeRouteTablesResult = describeRouteTablesMod.Result;
pub const RouteTable = describeRouteTablesMod.RouteTable;
pub const Route = describeRouteTablesMod.Route;
pub const RouteTableAssociation = describeRouteTablesMod.Association;

const describeInternetGatewaysMod = @import("describe/internet_gateways.zig");
const describeInternetGatewaysImpl = describeInternetGatewaysMod.describeInternetGateways;

pub const DescribeInternetGatewaysOptions = describeInternetGatewaysMod.Options;
pub const DescribeInternetGatewaysParams = describeInternetGatewaysMod.Params;
pub const DescribeInternetGatewaysResult = describeInternetGatewaysMod.Result;
pub const InternetGateway = describeInternetGatewaysMod.InternetGateway;
pub const InternetGatewayAttachment = describeInternetGatewaysMod.Attachment;

const describeNatGatewaysMod = @import("describe/nat_gateways.zig");
const describeNatGatewaysImpl = describeNatGatewaysMod.describeNatGateways;

pub const DescribeNatGatewaysOptions = describeNatGatewaysMod.Options;
pub const DescribeNatGatewaysParams = describeNatGatewaysMod.Params;
pub const DescribeNatGatewaysResult = describeNatGatewaysMod.Result;
pub const NatGateway = describeNatGatewaysMod.NatGateway;

const describeVpcPeeringConnectionsMod = @import("describe/vpc_peering_connections.zig");
const describeVpcPeeringConnectionsImpl = describeVpcPeeringConnectionsMod.describeVpcPeeringConnections;

pub const DescribeVpcPeeringConnectionsOptions = describeVpcPeeringConnectionsMod.Options;
pub const DescribeVpcPeeringConnectionsParams = describeVpcPeeringConnectionsMod.Params;
pub const DescribeVpcPeeringConnectionsResult = describeVpcPeeringConnectionsMod.Result;
pub const VpcPeeringConnection = describeVpcPeeringConnectionsMod.VpcPeeringConnection;

const describeTransitGatewayVpcAttachmentsMod = @import("describe/transit_gateway_vpc_attachments.zig");
const describeTransitGatewayVpcAttachmentsImpl = describeTransitGatewayVpcAttachmentsMod.describeTransitGatewayVpcAttachments;

pub const DescribeTransitGatewayVpcAttachmentsOptions = describeTransitGatewayVpcAttachmentsMod.Options;
pub const DescribeTransitGatewayVpcAttachmentsParams = describeTransitGatewayVpcAttachmentsMod.Params;
pub const DescribeTransitGatewayVpcAttachmentsResult = describeTransitGatewayVpcAttachmentsMod.Result;
pub const TransitGatewayVpcAttachment = describeTransitGatewayVpcAttachmentsMod.TransitGatewayVpcAttachment;

const describeVpcEndpointsMod = @import("describe/vpc_endpoints.zig");
const describeVpcEndpointsImpl = describeVpcEndpointsMod.describeVpcEndpoints;

pub const DescribeVpcEndpointsOptions = describeVpcEndpointsMod.Options;
pub const DescribeVpcEndpointsParams = describeVpcEndpointsMod.Params;
pub const DescribeVpcEndpointsResult = describeVpcEndpointsMod.Result;
pub const VpcEndpoint = describeVpcEndpointsMod.VpcEndpoint;

const describeVpnGatewaysMod = @import("describe/vpn_gateways.zig");
const describeVpnGatewaysImpl = describeVpnGatewaysMod.describeVpnGateways;

pub const DescribeVpnGatewaysOptions = describeVpnGatewaysMod.Options;
pub const DescribeVpnGatewaysParams = describeVpnGatewaysMod.Params;
pub const DescribeVpnGatewaysResult = describeVpnGatewaysMod.Result;
pub const VpnGateway = describeVpnGatewaysMod.VpnGateway;

const describeEgressOnlyInternetGatewaysMod = @import("describe/egress_only_internet_gateways.zig");
const describeEgressOnlyInternetGatewaysImpl = describeEgressOnlyInternetGatewaysMod.describeEgressOnlyInternetGateways;

pub const DescribeEgressOnlyInternetGatewaysOptions = describeEgressOnlyInternetGatewaysMod.Options;
pub const DescribeEgressOnlyInternetGatewaysParams = describeEgressOnlyInternetGatewaysMod.Params;
pub const DescribeEgressOnlyInternetGatewaysResult = describeEgressOnlyInternetGatewaysMod.Result;
pub const EgressOnlyInternetGateway = describeEgressOnlyInternetGatewaysMod.EgressOnlyInternetGateway;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    /// Override the EC2 endpoint (e.g. for LocalStack).
    endpoint_url: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    /// Owned.
    endpoint: []const u8,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try allocator.print("https://ec2.{s}.amazonaws.com", .{options.region});

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

    /// Describe VPCs. Caller owns the result and must call deinit.
    pub fn describeVpcs(self: *Client, options: DescribeVpcsOptions) !DescribeVpcsResult {
        return describeVpcsImpl(self, options);
    }

    /// Describe one attribute of a VPC. Caller owns the result and must call deinit.
    pub fn describeVpcAttribute(self: *Client, options: DescribeVpcAttributeOptions) !DescribeVpcAttributeResult {
        return describeVpcAttributeImpl(self, options);
    }

    /// Describe subnets. Caller owns the result and must call deinit.
    pub fn describeSubnets(self: *Client, options: DescribeSubnetsOptions) !DescribeSubnetsResult {
        return describeSubnetsImpl(self, options);
    }

    /// Describe DHCP options sets. Caller owns the result and must call deinit.
    pub fn describeDhcpOptions(self: *Client, options: DescribeDhcpOptionsOptions) !DescribeDhcpOptionsResult {
        return describeDhcpOptionsImpl(self, options);
    }

    /// Describe route tables. Caller owns the result and must call deinit.
    pub fn describeRouteTables(self: *Client, options: DescribeRouteTablesOptions) !DescribeRouteTablesResult {
        return describeRouteTablesImpl(self, options);
    }

    /// Describe internet gateways. Caller owns the result and must call deinit.
    pub fn describeInternetGateways(self: *Client, options: DescribeInternetGatewaysOptions) !DescribeInternetGatewaysResult {
        return describeInternetGatewaysImpl(self, options);
    }
    /// Describe NAT gateways. Caller owns the result and must call deinit.
    pub fn describeNatGateways(self: *Client, options: DescribeNatGatewaysOptions) !DescribeNatGatewaysResult {
        return describeNatGatewaysImpl(self, options);
    }
    /// Describe VPC peering connections. Caller owns the result and must call deinit.
    pub fn describeVpcPeeringConnections(self: *Client, options: DescribeVpcPeeringConnectionsOptions) !DescribeVpcPeeringConnectionsResult {
        return describeVpcPeeringConnectionsImpl(self, options);
    }
    /// Describe transit gateway VPC attachments. Caller owns the result and must call deinit.
    pub fn describeTransitGatewayVpcAttachments(self: *Client, options: DescribeTransitGatewayVpcAttachmentsOptions) !DescribeTransitGatewayVpcAttachmentsResult {
        return describeTransitGatewayVpcAttachmentsImpl(self, options);
    }
    /// Describe VPC endpoints. Caller owns the result and must call deinit.
    pub fn describeVpcEndpoints(self: *Client, options: DescribeVpcEndpointsOptions) !DescribeVpcEndpointsResult {
        return describeVpcEndpointsImpl(self, options);
    }
    /// Describe virtual private gateways. Caller owns the result and must call deinit.
    pub fn describeVpnGateways(self: *Client, options: DescribeVpnGatewaysOptions) !DescribeVpnGatewaysResult {
        return describeVpnGatewaysImpl(self, options);
    }
    /// Describe egress-only internet gateways. Caller owns the result and must call deinit.
    pub fn describeEgressOnlyInternetGateways(self: *Client, options: DescribeEgressOnlyInternetGatewaysOptions) !DescribeEgressOnlyInternetGatewaysResult {
        return describeEgressOnlyInternetGatewaysImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init regional endpoint" {
    var c = try Client.init(std.testing.allocator, .{
        .region = "eu-west-1",
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("https://ec2.eu-west-1.amazonaws.com", c.endpoint);
}

test "Client init custom endpoint" {
    var c = try Client.init(std.testing.allocator, .{
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
        .endpoint_url = "http://localhost:4566",
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("http://localhost:4566", c.endpoint);
}

test {
    _ = @import("describe/vpcs.zig");
    _ = @import("describe/vpc_attribute.zig");
    _ = @import("describe/subnets.zig");
    _ = @import("describe/dhcp_options.zig");
    _ = @import("describe/route_tables.zig");
    _ = @import("describe/internet_gateways.zig");
    _ = @import("describe/nat_gateways.zig");
    _ = @import("describe/vpc_peering_connections.zig");
    _ = @import("describe/transit_gateway_vpc_attachments.zig");
    _ = @import("describe/vpc_endpoints.zig");
    _ = @import("describe/vpn_gateways.zig");
    _ = @import("describe/egress_only_internet_gateways.zig");
    _ = @import("request.zig");
}
