const std = @import("std");
const nats = @import("nats");

pub fn main() !void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!general_purpose_allocator.deinit());
    const gpa = &general_purpose_allocator.allocator;

    var c = try nats.connect(gpa, .{
        .url = "localhost:4222",
        .servers = &.{},
        .name = "test",
    });
    defer c.deinit();

    c.subscribe("hello", null);

    while (true) {}
}
