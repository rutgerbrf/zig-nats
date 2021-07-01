const std = @import("std");
const Allocator = mem.Allocator;
const Thread = std.Thread;
const fmt = std.fmt;
const io = std.io;
const json = std.json;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const nkeys = @import("nkeys");
const nuid = @import("nuid.zig");
const testing = std.testing;
const tls = @import("iguanaTLS");
const uri = @import("uri");

const CountingWriter = struct {
    const Self = @This();
    const WriteError = error{};
    pub const Writer = io.Writer(*Self, WriteError, write);

    count: usize = 0,

    fn write(self: *Self, bytes: []const u8) WriteError!usize {
        self.count += bytes.len;
        return bytes.len;
    }

    fn writer(self: *Self) Writer {
        return .{ .context = self };
    }
};

// TODO(rutgerbrf): Cancellation!
pub const Conn = struct {
    const Self = @This();
    // TODO(rutgerbrf): has_protocol? (the 4th param)
    const TlsClient = tls.Client(net.Stream.Reader, net.Stream.Writer, tls.ciphersuites.all, false);
    const ReadError = net.Stream.Reader.Error || TlsClient.Reader.Error;
    const WriteError = net.Stream.Writer.Error || TlsClient.Writer.Error;
    const Reader = io.Reader(*Self, ReadError, read);
    const Writer = io.Writer(*Self, WriteError, write);

    allocator: *Allocator,
    strm: net.Stream,
    tlsc: ?TlsClient = null,
    headers: bool,

    fn read(self: *Self, dest: []u8) ReadError!usize {
        return if (self.tlsc) |*tlss| try tlss.read(dest) else try self.strm.read(dest);
    }

    fn write(self: *Self, bytes: []const u8) WriteError!usize {
        return if (self.tlsc) |*tlss| try tlss.write(bytes) else try self.strm.write(bytes);
    }

    fn reader(self: *Self) Reader {
        return .{ .context = self };
    }

    fn writer(self: *Self) Writer {
        return .{ .context = self };
    }

    fn readServerOp(self: *Self) !ServerOp {
        return ServerOp.readFrom(self.allocator, self.reader());
    }

    fn freeServerOp(self: *const Self, op: *ServerOp) void {
        // TODO(rutgerbrf): wipe the memory before freeing it
        op.readFromFree(self.allocator);
    }

    fn writeClientOp(self: *Self, op: *const ClientOp) !void {
        return ClientOp.writeTo(op, self.writer());
    }

    fn fromNewStream(allocator: *Allocator, server: Server, strm: net.Stream) !Conn {
        var c = Conn{ .allocator = allocator, .strm = strm, .headers = false };
        std.debug.print("Reading server op\n", .{});
        var server_op = try c.readServerOp();
        defer c.freeServerOp(&server_op);
        std.debug.print("Read server op\n", .{});

        var tls_required = server.tls_required;
        switch (server_op) {
            .info => |info| {
                c.headers = info.headers orelse false;
                tls_required = tls_required or (info.tls_required orelse false);
            },
            else => return error.UnexpectedServerOp,
        }

        if (c.headers) std.debug.print("Server has support for headers\n", .{});
        if (tls_required) {
            c.tlsc = try tls.client_connect(.{
                .cert_verifier = .none,
                .reader = c.strm.reader(),
                .writer = c.strm.writer(),
                .temp_allocator = allocator,
            }, server.host); // TODO(rutgerbrf): make sure the DNS name is valid, or do some stuff with it
        }

        var connect_op = ConnectOp{
            .verbose = false,
            .pedantic = false,
            .user_jwt = null,
            .nkey = null,
            .signature = null,
            .name = "hello",
            //            .name = opts.name,
            //            .echo = opts.echo,
            .echo = false,
            .lang = "zig",
            .version = "who knows", // TODO(rutgerbrf)
            .tls_required = tls_required,
            .user = null,
            .pass = null,
            .auth_token = null,
            .headers = true,
        };

        try c.writeClientOp(&.{ .connect = connect_op });

        const ping: ClientOp = .ping;
        const pong: ClientOp = .pong;
        try c.writeClientOp(&ping);

        while (true) {
            var maybe_pong = try c.readServerOp();
            defer c.freeServerOp(&maybe_pong);
            switch (maybe_pong) {
                .pong => break,
                .ping => try c.writeClientOp(&pong),
                else => return error.InvalidData,
            }
        }

        return c;
    }
};

const Client = struct {
    const Self = @This();

    allocator: *Allocator,
    conn: Conn,
    thread: ?*Thread = null,
    last_subscription_id: u64 = 0,

    fn queue(self: *Self, op: *const ClientOp) void {
        // TODO(rutgerbrf): make this safe, report errors and stuff
        self.conn.writeClientOp(op) catch |e| std.log.err("oops: {}", .{e});
    }

    fn run(self: *Self) void {
        var count: usize = 0;
        while (true) {
            var server_op = self.conn.readServerOp() catch |e| {
                std.log.err("Sad life: {}", .{e});
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpStackTrace(trace.*);
                }
                return;
            }; // TODO(rutgerbrf): handle this correctly
            defer self.conn.freeServerOp(&server_op);
            count += 1;

            if (count % 100000 == 0) {
                std.log.info("Read {} server ops", .{count});
            }

            const pong: ClientOp = .pong;
            switch (server_op) {
                .ping => self.queue(&pong),
                else => {},
            }
        }
    }

    fn newSubscriptionId(self: *Self) u64 {
        self.last_subscription_id += 1;
        return self.last_subscription_id;
    }

    pub fn subscribe(self: *Self, subject: []const u8, queue_group: ?[]const u8) void {
        var op = SubOp{
            .subject = subject,
            .queue_group = queue_group,
            .subscription_id = self.newSubscriptionId(),
        };
        self.queue(&.{ .subscribe = op });
    }

    fn init(allocator: *Allocator, conn: Conn) !*Self {
        const self = try allocator.create(Self);
        self.* = Client{ .allocator = allocator, .conn = conn };
        return self;
    }

    fn start(self: *Self) !void {
        self.thread = try Thread.spawn(Self.run, self);
    }

    pub fn deinit(self: *Self) void {
        // TODO(rutgerbrf): close the connection
        self.allocator.destroy(self);
    }
};

pub fn connect(allocator: *Allocator, options: ClientOptions) !*Client {
    const server = try Server.fromUrl(options.url);
    const strm = try net.tcpConnectToHost(allocator, server.host, server.port);
    const conn = try Conn.fromNewStream(allocator, server, strm);
    const client = try Client.init(allocator, conn);
    try client.start();
    return client;
}

const Server = struct {
    const Self = @This();

    host: []const u8,
    port: u16,
    tls_required: bool,

    fn fromUrl(url: []const u8) !Self {
        const tls_required = mem.startsWith(u8, url, "tls://");
        const host_port = if (mem.indexOf(u8, url, "://")) |sep_idx| url[sep_idx..] else url;
        if (host_port.len == 0) return error.BadHostPort; // TODO
        var addr = splitHostPort(host_port) catch HostPort{ .host = host_port, .port = "4222" };
        for (addr.port) |c| if (!std.ascii.isDigit(c)) return error.NonNumericalPort;
        var port = fmt.parseInt(u16, addr.port, 10) catch return error.PortTooLong;

        return Self{
            .host = addr.host,
            .port = port,
            .tls_required = tls_required,
        };
    }

    const HostPort = struct {
        host: []const u8,
        port: []const u8,
    };

    // Taken from the Go standard library.
    fn splitHostPort(host_port: []const u8) !HostPort {
        var host: []const u8 = host_port;
        var j: usize = 0;
        var k: usize = 0;

        // The port starts after the last colon.
        var i = mem.lastIndexOf(u8, host_port, ":") orelse return error.MissingPort;

        if (host_port[0] == '[') {
            var end = mem.indexOf(u8, host_port, "]") orelse return error.MissingClosingBracket;
            if (end + 1 == host_port.len) return error.MissingPort; // There can't be a ':' behind the ']' now.
            if (end + 1 != i) {
                // Either ']' isn't followed by a colon, or it is followed by a colon that is not the last one.
                if (host_port[end + 1] == ':') return error.TooManyColons;
                return error.MissingPort;
            }
            host = host_port[1..end];
            j = 1;
            k = end + 1;
        } else {
            host = host_port[0..i];
            if (mem.indexOf(u8, host, ":") != null) return error.TooManyColons;
        }
        if (mem.indexOf(u8, host_port[j..], "[") != null) return error.UnexpectedOpeningBracket;
        if (mem.indexOf(u8, host_port[k..], "]") != null) return error.UnexpectedClosingBracket;

        var port = host_port[i + 1 ..];
        return HostPort{ .host = host, .port = port };
    }
};

pub const ClientOptions = struct {
    url: []const u8,
    servers: []const []const Server,
    // no_randomize: bool,
    name: []const u8,
    // verbose: bool,
    // pedantic: bool,
    // secure: bool,
    // tls_config: TlsConfig // dependent on TLS lib 
    // allow_reconnect: bool = true,
    // max_reconnect: usize = default_max_reconnect,
    // reconnect_wait: time.Duration,
    // custom_reconnect_delay_cb: ReconnectDelayHandler,
    // reconnect_jitter: time.Duration,
    // reconnect_jitter_tls: time.Duration,
    // drain_timeout: time.Duration,
    // flusher_timeout: time.Duration,
    // ping_interval: time.Duration,
    // max_pings_out: usize,
    // closed_cb: ConnHandler,
    // disconnected_err_cb: ConnErrHandler,
    // reconnected_cb: ConnHandler,
    // discovered_servers_cb: ConnHandler,
    // async_error_cb: ErrHandler,
    // reconnect_buf_size: usize,
    // sub_chan_len: usize, // may not be applicable
    // user_jwt: UserJwtHandler,
    // nkey: []const u8,
    // sinature_cb: SignatureHandler,
    // user: []const u8,
    // password: []const u8,
    // token: []const u8,
    // token_handler: AuthTokenHandler,
    // custom_dialer: CustomDialer, // may not be applicable, Go-specific?
    // use_old_request_style: bool,
    // no_callbacks_after_client_close: bool,
    // lame_duck_mode_handler: ConnHandler,
    // retry_on_failed_connect: bool,
    // compression: bool, // only for WebSockets, add support later on
};

pub const Headers = struct {
    const Self = @This();

    entries: std.StringHashMap(std.ArrayList([]const u8)),

    fn init(allocator: *Allocator) Self {
        return .{
            .entries = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
        };
    }

    fn deinit(self: *Self) void {
        var iterator = self.entries.iterator();
        while (iterator.next()) |it| it.value_ptr.deinit();
        self.entries.deinit();
    }

    fn calcSize(self: *const Self) usize {
        var w = CountingWriter{};
        self.writeTo(w.writer()) catch unreachable; // TODO(rutgerbrf): this unreachable won't be quite so unreachable anymore if writeTo starts returning errors of its own
        return w.count;
    }

    fn writeTo(self: *const Self, out_stream: anytype) @TypeOf(out_stream).Error!void {
        var iterator = self.entries.iterator();
        try out_stream.writeAll("NATS/1.0");
        if (self.entries.get("Status")) |statuses| {
            if (statuses.items.len > 0) {
                try out_stream.writeAll(" ");
                // TODO(rutgerbrf): check value
                try out_stream.writeAll(statuses.items[0]);
            }
        }
        try out_stream.writeAll("\r\n");
        while (iterator.next()) |it| {
            var values = it.value_ptr.items;
            if (std.mem.eql(u8, it.key_ptr.*, "Status") and values.len > 0) {
                values = it.value_ptr.items[1..];
            }
            for (values) |val| {
                // TODO(rutgerbrf): check key
                try out_stream.writeAll(it.key_ptr.*);
                try out_stream.writeAll(": ");
                // TODO(rutgerbrf): check value
                try out_stream.writeAll(val);
                try out_stream.writeAll("\r\n");
            }
        }
        try out_stream.writeAll("\r\n");
    }

    fn readFrom(allocator: *Allocator, buf: []const u8) !Self {
        const header_first_line = "NATS/1.0";
        const status_header = "Status";
        const space = &[_]u8{ ' ', '\t', 0x0B, 0x0C };

        var self = Self.init(allocator);
        errdefer self.deinit();

        var first_line = true;
        var lines = mem.split(buf, "\r\n");
        while (lines.next()) |line| {
            if (line.len > 0 and lines.index == null) return error.BadHeaderMsg;

            if (first_line) {
                first_line = false;

                if (!mem.startsWith(u8, line, header_first_line)) {
                    return error.BadHeaderMsg;
                }
                if (line.len > header_first_line.len) {
                    var i = header_first_line.len;
                    for (line[header_first_line.len..]) |c| {
                        if (mem.indexOf(u8, space, &.{c}) == null) break;
                        i += 1;
                    }

                    if (i == header_first_line.len) return error.BadHeaderMsg;

                    var status = mem.trim(u8, line[i..], space);
                    if (status.len != 3) return error.BadHeaderMsg; // 3.., 4.., 5..

                    var list = std.ArrayList([]const u8).init(allocator);
                    try list.append(status);
                    try self.entries.put(status_header, list);
                }

                continue;
            }

            if (line.len == 0) break;

            var i = mem.indexOf(u8, line, ":") orelse return error.BadHeaderMsg;
            const key = line[0..i];
            if (key.len == 0) continue;
            i += 1;
            while (i < line.len and (line[i] == ' ' or line[i] == '\t')) {
                i += 1;
            }
            const value = line[i..];
            const result = try self.entries.getOrPut(key);
            if (!result.found_existing) {
                result.value_ptr.* = std.ArrayList([]const u8).init(allocator);
            }
            try result.value_ptr.append(value);
        }

        return self;
    }
};

const ClientOp = union(enum) {
    const Self = @This();

    connect: ConnectOp,
    publish: PubOp,
    hpublish: HpubOp,
    subscribe: SubOp,
    unsubscribe: UnsubOp,
    ping,
    pong,

    fn writeTo(self: *const Self, out_stream: anytype) !void {
        switch (self.*) {
            .connect => |*op| try op.writeTo(out_stream),
            .publish => |*op| try op.writeTo(out_stream),
            .hpublish => |*op| try op.writeTo(out_stream),
            .subscribe => |*op| try op.writeTo(out_stream),
            .unsubscribe => |*op| try op.writeTo(out_stream),
            .ping => try out_stream.writeAll("PING\r\n"),
            .pong => try out_stream.writeAll("PONG\r\n"),
        }
    }
};

const ConnectOp = struct {
    const Self = @This();

    verbose: bool,
    pedantic: bool,
    user_jwt: ?[]const u8,
    nkey: ?[]const u8,
    signature: ?[]const u8,
    name: ?[]const u8,
    echo: bool,
    lang: []const u8,
    version: []const u8,
    tls_required: bool,
    user: ?[]const u8,
    pass: ?[]const u8,
    auth_token: ?[]const u8,
    headers: bool,

    fn writeTo(self: *const Self, out_stream: anytype) @TypeOf(out_stream).Error!void {
        try out_stream.writeAll("CONNECT ");
        try json.stringify(self.*, .{}, out_stream);
        try out_stream.writeAll("\r\n");
    }
};

const PubOp = struct {
    const Self = @This();

    subject: []const u8,
    reply_to: ?[]const u8,
    payload: []const u8,

    fn writeTo(self: *const Self, out_stream: anytype) @TypeOf(out_stream).Error!void {
        try out_stream.writeAll("PUB ");
        // TODO(rutgerbrf): validate subject, reply_to?
        try out_stream.writeAll(self.subject);
        try out_stream.writeAll(" ");
        if (self.reply_to) |reply_to| {
            try out_stream.writeAll(reply_to);
            try out_stream.writeAll(" ");
        }
        try fmt.formatInt(self.payload.len, 10, .lower, .{}, out_stream);
        try out_stream.writeAll("\r\n");
        try out_stream.writeAll(self.payload);
        try out_stream.writeAll("\r\n");
    }
};

const HpubOp = struct {
    const Self = @This();

    subject: []const u8,
    reply_to: ?[]const u8,
    headers: Headers,
    payload: []const u8,

    fn writeTo(self: *const Self, out_stream: anytype) @TypeOf(out_stream).Error!void {
        try out_stream.writeAll("HPUB ");
        // TODO(rutgerbrf): validate subject, reply_to?
        try out_stream.writeAll(self.subject);
        try out_stream.writeAll(" ");
        if (self.reply_to) |reply_to| {
            try out_stream.writeAll(reply_to);
            try out_stream.writeAll(" ");
        }
        const headers_size = self.headers.calcSize();
        try fmt.formatInt(headers_size, 10, .lower, .{}, out_stream);
        try out_stream.writeAll(" ");
        const total_size = headers_size + self.payload.len;
        try fmt.formatInt(total_size, 10, .lower, .{}, out_stream);
        try out_stream.writeAll("\r\n");
        try self.headers.writeTo(out_stream);
        try out_stream.writeAll(self.payload);
        try out_stream.writeAll("\r\n");
    }
};

const SubOp = struct {
    const Self = @This();

    subject: []const u8,
    queue_group: ?[]const u8,
    subscription_id: u64,

    fn writeTo(self: *const Self, out_stream: anytype) @TypeOf(out_stream).Error!void {
        try out_stream.writeAll("SUB ");
        // TODO(rutgerbrf): validate subject, queue_group?
        try out_stream.writeAll(self.subject);
        try out_stream.writeAll(" ");
        if (self.queue_group) |queue_group| {
            try out_stream.writeAll(queue_group);
            try out_stream.writeAll(" ");
        }
        try fmt.formatInt(self.subscription_id, 10, .lower, .{}, out_stream);
        try out_stream.writeAll("\r\n");
    }
};

const UnsubOp = struct {
    const Self = @This();

    subscription_id: u64,
    max_msgs: ?u64,

    fn writeTo(self: *const Self, out_stream: anytype) @TypeOf(out_stream).Error!void {
        try out_stream.writeAll("UNSUB ");
        try fmt.formatInt(self.subscription_id, 10, .lower, .{}, out_stream);
        if (self.max_msgs) |max_msgs| {
            try out_stream.writeAll(" ");
            try fmt.formatInt(max_msgs, 10, .lower, .{}, out_stream);
        }
        try out_stream.writeAll("\r\n");
    }
};

const ProtocolError = error{ InvalidData, EndOfStream };

const ServerOp = union(enum) {
    const Self = @This();

    info: InfoOp,
    msg: MsgOp,
    hmsg: HmsgOp,
    ping,
    pong,
    err: ErrOp,
    ok,
    unknown: []const u8,

    fn readFromFree(self: *Self, allocator: *Allocator) void {
        switch (self.*) {
            .info => |*op| op.readFromFree(allocator),
            .msg => |*op| op.readFromFree(allocator),
            .hmsg => |*op| op.readFromFree(allocator),
            .err => |*op| op.readFromFree(allocator),
            else => {},
        }
    }

    fn assertNext(comptime bs: []const u8, in_stream: anytype) (@TypeOf(in_stream).Error || ProtocolError)!void {
        for (bs) |b| {
            const read = try in_stream.readByte();
            if (read != b) return error.InvalidData;
        }
    }

    fn readFrom(allocator: *Allocator, in_stream: anytype) !Self {
        // INFO / MSG / HMSG / PING / PONG / ERR / ?
        var b0 = try in_stream.readByte();
        switch (b0) {
            'I' => {
                try assertNext("NFO ", in_stream);
                return Self{ .info = try InfoOp.readFrom(allocator, in_stream) };
            },
            'M' => {
                try assertNext("SG ", in_stream);
                return Self{ .msg = try MsgOp.readFrom(allocator, in_stream) };
            },
            'H' => {
                try assertNext("MSG ", in_stream);
                return Self{ .hmsg = try HmsgOp.readFrom(allocator, in_stream) };
            },
            'P' => {
                var b1 = try in_stream.readByte();
                switch (b1) {
                    'I' => {
                        try assertNext("NG\r\n", in_stream);
                        return Self.ping;
                    },
                    'O' => {
                        try assertNext("NG\r\n", in_stream);
                        return Self.pong;
                    },
                    else => return error.InvalidData,
                }
            },
            '-' => {
                try assertNext("ERR ", in_stream);
                return Self{ .err = try ErrOp.readFrom(allocator, in_stream) };
            },
            '+' => {
                try assertNext("OK\r\n", in_stream);
                return Self.ok;
            },
            else => return error.InvalidData,
        }
    }
};

const InfoOp = struct {
    const Self = @This();

    server_id: []const u8,
    server_name: []const u8,
    proto: i32,
    host: []const u8,
    port: u16,
    max_payload: i64,
    headers: ?bool = null,
    auth_required: ?bool = null,
    tls_required: ?bool = null,
    tls_available: ?bool = null,
    client_id: ?u64 = null,
    client_ip: ?[]const u8 = null,
    nonce: ?[]const u8 = null,
    cluster: ?[]const u8 = null,
    connect_urls: ?[][]const u8 = null,
    lame_duck_mode: ?bool = null,

    fn parseOpts(allocator: *Allocator) json.ParseOptions {
        return .{ .allocator = allocator, .ignore_unknown_fields = true };
    }

    fn readFromFree(self: *Self, allocator: *Allocator) void {
        return json.parseFree(Self, self.*, parseOpts(allocator));
    }

    fn readFrom(allocator: *Allocator, in_stream: anytype) !Self {
        var buf = try in_stream.readUntilDelimiterAlloc(allocator, '\r', std.math.maxInt(usize)); // TODO(rutgerbrf): make the limit configurable
        const json_buf = buf[0 .. buf.len - 1]; // without the '\r'
        defer allocator.free(buf);
        var lf = try in_stream.readByte();
        if (lf != '\n') return error.InvalidData;

        std.debug.print("Parsing the following JSON: '{s}'\n", .{json_buf});

        @setEvalBranchQuota(1_000_000); // TODO(rutgerbrf): this might be somewhat excessive
        return json.parse(Self, &json.TokenStream.init(json_buf), parseOpts(allocator));
    }
};

const MsgOp = struct {
    const Self = @This();

    _ctrl_buf: []const u8,
    subject: []const u8,
    subscription_id: u64,
    reply_to: ?[]const u8,
    payload: []const u8,

    fn readFromFree(self: *Self, allocator: *Allocator) void {
        allocator.free(self._ctrl_buf);
        allocator.free(self.payload);
    }

    fn readFrom(allocator: *Allocator, in_stream: anytype) !Self {
        var control = try in_stream.readUntilDelimiterAlloc(allocator, '\r', std.math.maxInt(usize)); // TODO(rutgerbrf): make the limit configurable
        var lf = try in_stream.readByte();
        if (lf != '\n') return error.InvalidData;

        var parts = [_]?[]const u8{null} ** 4;

        var tokens = mem.tokenize(control, " ");
        var i: usize = 0;
        while (tokens.next()) |token| {
            parts[i] = token;
            i += 1;
        }
        if (i < 3 or i > 4) return error.InvalidData;

        var has_reply_to = i == 4;
        var subject = parts[0].?;
        var subscription_id = try fmt.parseInt(u64, parts[1].?, 10);
        var reply_to = if (i == 4) parts[2].? else null;
        var payload_len = try fmt.parseInt(u64, if (has_reply_to) parts[3].? else parts[2].?, 10);

        var payload_buf = try allocator.alloc(u8, payload_len);
        try in_stream.readNoEof(payload_buf);

        var cr = try in_stream.readByte();
        if (cr != '\r') return error.InvalidData;
        lf = try in_stream.readByte();
        if (lf != '\n') return error.InvalidData;

        return Self{
            ._ctrl_buf = control,
            .subject = subject,
            .subscription_id = subscription_id,
            .reply_to = reply_to,
            .payload = payload_buf,
        };
    }
};

const HmsgOp = struct {
    const Self = @This();

    _ctrl_buf: []const u8,
    subject: []const u8,
    subscription_id: u64,
    reply_to: ?[]const u8,
    _hdrs_buf: []const u8,
    headers: Headers,
    payload: []const u8,

    fn readFromFree(self: *Self, allocator: *Allocator) void {
        allocator.free(self._ctrl_buf);
        self.headers.deinit();
        allocator.free(self._hdrs_buf);
    }

    fn readFrom(allocator: *Allocator, in_stream: anytype) !Self {
        var control = try in_stream.readUntilDelimiterAlloc(allocator, '\r', std.math.maxInt(usize)); // TODO(rutgerbrf): make the limit configurable
        var lf = try in_stream.readByte();
        if (lf != '\n') return error.InvalidData;

        var parts = [_]?[]const u8{null} ** 5;

        var tokens = mem.tokenize(control, " ");
        var i: usize = 0;
        while (tokens.next()) |token| {
            parts[i] = token;
            i += 1;
        }
        if (i < 4 or i > 5) return error.InvalidData;

        var has_reply_to = i == 5;
        var subject = parts[0].?;
        var subscription_id = try fmt.parseInt(u64, parts[1].?, 10);
        var reply_to = if (i == 5) parts[2].? else null;
        var header_len = try fmt.parseInt(u64, if (has_reply_to) parts[3].? else parts[2].?, 10);
        var total_len = try fmt.parseInt(u64, if (has_reply_to) parts[4].? else parts[3].?, 10);
        std.debug.assert(total_len >= header_len);

        var headers_buf = try allocator.alloc(u8, header_len);
        try in_stream.readNoEof(headers_buf);
        var payload_buf = try allocator.alloc(u8, total_len - header_len);
        try in_stream.readNoEof(payload_buf);

        var headers = try Headers.readFrom(allocator, headers_buf);

        var cr = try in_stream.readByte();
        if (cr != '\r') return error.InvalidData;
        lf = try in_stream.readByte();
        if (lf != '\n') return error.InvalidData;

        return Self{
            ._ctrl_buf = control,
            .subject = subject,
            .subscription_id = subscription_id,
            .reply_to = reply_to,
            ._hdrs_buf = headers_buf,
            .headers = headers,
            .payload = payload_buf,
        };
    }
};

const ErrOp = struct {
    const Self = @This();

    message: []const u8,

    fn readFromFree(self: *Self, allocator: *Allocator) void {
        allocator.free(self.message);
    }

    fn readFrom(allocator: *Allocator, in_stream: anytype) !Self {
        var buf = try in_stream.readUntilDelimiterAlloc(allocator, '\r', std.math.maxInt(usize)); // TODO(rutgerbrf): make the limit configurable
        var lf = try in_stream.readByte();
        if (lf != '\n') return error.InvalidData;
        return Self{ .message = buf };
    }
};

const Auth = union(enum) {
    none,
    user_pass: struct {
        user: []const u8,
        pass: []const u8,
    },
    token: []const u8,
    credentials: struct {},
    nkey: struct {},
};

fn CallbackType(comptime Arg: type, comptime Out: type) type {
    return struct {
        const Self = @This();

        const CallFn = fn (context: usize, arg: Arg) Out;

        internal: struct {
            context: usize,
            call: CallFn,
        },

        fn from(
            context: anytype,
            sign: fn (context: @TypeOf(context), arg: Arg) Out,
        ) Self {
            return .{
                .internal = .{
                    .context = @ptrToInt(context),
                    .call = @intToPtr(CallFn, @ptrToInt(sign)),
                },
            };
        }

        fn call(self: Self, buf: []const u8) anyerror![]const u8 {
            return self.internal.call(self.internal.context, buf);
        }
    };
}

const SignatureCallback = CallbackType([]const u8, anyerror![]const u8);
const JwtCallback = CallbackType(null, anyerror![]const u8);
const NkeyCallback = CallbackType(null, anyerror!nkeys.PublicKey);

test {
    testing.refAllDecls(@This());
    testing.refAllDecls(Conn);
    testing.refAllDecls(Headers);
    testing.refAllDecls(ClientOp);
    testing.refAllDecls(ConnectOp);
    testing.refAllDecls(PubOp);
    testing.refAllDecls(HpubOp);
    testing.refAllDecls(SubOp);
    testing.refAllDecls(UnsubOp);
    testing.refAllDecls(ServerOp);
    testing.refAllDecls(InfoOp);
    testing.refAllDecls(MsgOp);
    testing.refAllDecls(HmsgOp);
    testing.refAllDecls(ErrOp);

    testing.refAllDecls(Server);

    testing.refAllDecls(SignatureCallback);

    const context = struct {
        hello: []const u8 = "tsdfi9012843",

        fn example(self: *const @This(), buf: []const u8) anyerror![]const u8 {
            return self.hello;
        }
    }{};
    const cb = SignatureCallback.from(&context, @TypeOf(context).example, null);
    std.debug.print("{s}\n", .{try cb.call("asdf")});
}

test "parse header" {
    const wrong1 = "NATS/1.0";
    try testing.expectError(error.BadHeaderMsg, Headers.readFrom(testing.allocator, wrong1));

    const wrong2 = "NATS/1.0418";
    try testing.expectError(error.BadHeaderMsg, Headers.readFrom(testing.allocator, wrong2));

    const right1 = "NATS/1.0\r\n";
    var right1_res = try Headers.readFrom(testing.allocator, right1);
    defer right1_res.deinit();

    const right2 = "NATS/1.0 418\r\n";
    var right2_res = try Headers.readFrom(testing.allocator, right2);
    defer right2_res.deinit();
    try testing.expect(mem.eql(u8, right2_res.entries.get("Status").?.items[0], "418"));

    const wrong3 = "NATS/1.0 418\r\nStatus: 420";
    try testing.expectError(error.BadHeaderMsg, Headers.readFrom(testing.allocator, wrong3));

    const right3 = "NATS/1.0 418\r\nStatus: 420\r\n";
    var right3_res = try Headers.readFrom(testing.allocator, right3);
    defer right3_res.deinit();
    try testing.expect(mem.eql(u8, right3_res.entries.get("Status").?.items[0], "418"));
    try testing.expect(mem.eql(u8, right3_res.entries.get("Status").?.items[1], "420"));

    const wrong4 = "NATS/1.0\r\nExample: test";
    try testing.expectError(error.BadHeaderMsg, Headers.readFrom(testing.allocator, wrong4));

    const right4 = "NATS/1.0\r\nExample: test\r\n";
    var right4_res = try Headers.readFrom(testing.allocator, right4);
    defer right4_res.deinit();
    try testing.expect(mem.eql(u8, right4_res.entries.get("Example").?.items[0], "test"));
}
