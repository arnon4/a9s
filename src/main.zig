const std = @import("std");
const App = @import("app/app.zig").App;
const log = @import("log.zig");

test {
    _ = @import("app/views/lambda/lambda.zig");
    _ = @import("app/views/lambda/lambda_content.zig");
    _ = @import("app/views/s3/object_content.zig");
    _ = @import("app/views/s3/object.zig");
    _ = @import("app/views/s3/objects.zig");
    _ = @import("app/views/s3/buckets.zig");
    _ = @import("app/views/auth/credentials.zig");
    _ = @import("sdk/clients/lambda/client.zig");
    _ = @import("sdk/clients/s3/client.zig");
    _ = @import("sdk/clients/logs/client.zig");
    _ = @import("sdk/clients/iam/client.zig");
    _ = @import("sdk/clients/ec2/client.zig");
    _ = @import("app/views/vpc/vpc_home.zig");
    _ = @import("app/views/vpc/vpcs.zig");
    _ = @import("app/views/vpc/vpc.zig");
    _ = @import("app/views/vpc/subnets.zig");
    _ = @import("app/views/vpc/subnet.zig");
    _ = @import("app/views/vpc/dhcp_options.zig");
    _ = @import("app/views/vpc/route_tables.zig");
    _ = @import("app/views/vpc/route_table.zig");
    _ = @import("app/views/vpc/route_table_routes.zig");
    _ = @import("app/views/vpc/internet_gateways.zig");
    _ = @import("app/views/vpc/internet_gateway.zig");
    _ = @import("app/views/vpc/network_map.zig");
    _ = @import("app/views/vpc/network_map_graph.zig");
    _ = @import("app/views/logs/log_groups.zig");
}

pub const std_options: std.Options = .{
    .logFn = log.logFn,
};

pub fn main(init: std.process.Init) !void {
    try log.init(init.io, "a9s.log");
    defer log.deinit(init.io);

    const stdout = std.Io.File.stdout();
    var buf: [1024]u8 = undefined;
    var writer = stdout.writer(init.io, &buf);

    var app = try App.init(init.io, &writer.interface, init.gpa, init.environ_map, init.minimal.environ);
    defer app.deinit();
    try app.run();
}
