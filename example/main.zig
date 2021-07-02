const std = @import("std");
const nats = @import("nats");

pub const io_mode = .evented;

pub fn main() !void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!general_purpose_allocator.deinit());
    const gpa = &general_purpose_allocator.allocator;

    var c = try nats.connect(gpa, .{
        .url = "localhost:4222",
        .servers = &.{},
        .name = "test",
    }, null);
    defer c.deinit();

    const OnHello = struct {
        _: ?void = null,

        fn handleMessage(self: *@This(), msg: *nats.Msg) void {
            self._ = null;
            std.log.info("Got a message on subject {s}", .{msg.subject});
        }
    };
    var on_hello = OnHello{};
    try c.subscribe("hello", nats.MsgCallback.from(&on_hello, OnHello.handleMessage));

    while (true) {}
}


