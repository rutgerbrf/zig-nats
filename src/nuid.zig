const std = @import("std");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const rand = std.rand;
const testing = std.testing;

const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const min_inc: u63 = 33;
const max_inc: u63 = 333;
const base: u6 = 62;
const max_seq: u63 = math.pow(u63, base, seq_len);
const pre_len: usize = 12;
const seq_len: usize = 10;
const nuid_len = pre_len + seq_len;

var global_nuid: ?Nuid = null;
var global_nuid_lock = std.Thread.Mutex{};

pub fn next() [nuid_len]u8 {
    const lock = global_nuid_lock.acquire();
    defer lock.release();
    if (global_nuid == null) global_nuid = Nuid.init();
    return global_nuid.?.next();
}

pub const Nuid = struct {
    const Self = @This();

    rng: rand.Gimli,
    pre: [pre_len]u8,
    seq: u63,
    inc: u63,

    pub fn init() Self {
        var seed: [rand.Gimli.secret_seed_length]u8 = undefined;
        crypto.random.bytes(&seed);

        var rng = rand.Gimli.init(seed);
        var n = Self{
            .rng = rng,
            .seq = rng.random.uintLessThan(u63, max_seq),
            .inc = min_inc + rng.random.uintLessThan(u63, max_inc - min_inc),
            .pre = [_]u8{0} ** pre_len,
        };
        n.randomizePrefix();

        return n;
    }

    pub fn next(self: *Self) [nuid_len]u8 {
        self.seq += self.inc;
        if (self.seq >= max_seq) {
            self.randomizePrefix();
            self.resetSequential();
        }
        var seq = self.seq;

        var bs: [nuid_len]u8 = undefined;
        mem.copy(u8, &bs, &self.pre);

        var i = bs.len;
        while (i > pre_len) : (seq /= base) {
            i -= 1;
            bs[i] = chars[seq % base];
        }
        return bs;
    }

    pub fn randomizePrefix(self: *Self) void {
        var cb: [pre_len]u8 = undefined;
        crypto.random.bytes(&cb);

        var i: usize = 0;
        while (i < pre_len) : (i += 1) {
            self.pre[i] = chars[cb[i] % base];
        }
    }

    fn resetSequential(self: *Self) void {
        self.seq = self.rng.random.uintLessThan(u63, max_seq);
        self.inc = min_inc + self.rng.random.uintLessThan(u63, max_inc - min_inc);
    }
};

test {
    testing.refAllDecls(@This());
    testing.refAllDecls(Nuid);
}

test "chars" {
    try testing.expect(chars.len == base);
}

test "global next" {
    _ = next(); // this shouldn't crash
}

test "NUID rollover" {
    if (global_nuid == null) global_nuid = Nuid.init();
    global_nuid.?.seq = max_seq;

    var old_pre = global_nuid.?.pre;
    _ = next();

    try testing.expect(!mem.eql(u8, &global_nuid.?.pre, &old_pre));
}

test "proper prefix" {
    var min: u8 = 255;
    var max: u8 = 0;
    for (chars) |c| {
        if (c < min) {
            min = c;
        } else if (c > max) {
            max = c;
        }
    }
    var total: usize = 100_000;
    while (total > 0) : (total -= 1) {
        var nuid = Nuid.init();
        for (nuid.pre) |c| {
            try testing.expect(c >= min and c <= max);
        }
    }
}

test "uniqueness" {
    const n: usize = 10_000_000;
    var all: [][nuid_len]u8 = try testing.allocator.alloc([nuid_len]u8, n);
    defer testing.allocator.free(all);
    var s = std.StringHashMap(void).init(testing.allocator);
    defer s.deinit();

    var i: usize = 0;
    while (i < n) : (i += 1) {
        all[i] = next();
        try testing.expect(!s.contains(&all[i]));
        try s.put(&all[i], undefined);
    }
}

test "bench Nuid speed" {
    const time = std.time;

    var nuid = Nuid.init();
    const n: usize = 100_000_000;
    var start = time.nanoTimestamp();
    var i: usize = 0;
    while (i < n) : (i += 1) {
        _ = nuid.next();
    }
    var end = time.nanoTimestamp();

    var diff = @intCast(u127, end - start);
    var seconds = diff / math.pow(u127, 10, 9);
    var nanos = diff % math.pow(u127, 10, 9);
    std.debug.print("Generated {d} NUIDs in {d}.{:0.9}s\n", .{ i, seconds, nanos });
    std.debug.print("That's {d}ns per NUID\n", .{diff / n});
}

test "bench global Nuid speed" {
    const time = std.time;

    const n: usize = 100_000_000;
    var start = time.nanoTimestamp();
    var i: usize = 0;
    while (i < n) : (i += 1) {
        _ = next();
    }
    var end = time.nanoTimestamp();

    var diff = @intCast(u127, end - start);
    var seconds = diff / math.pow(u127, 10, 9);
    var nanos = diff % math.pow(u127, 10, 9);
    std.debug.print("Global Nuid generated {d} NUIDs in {d}.{:0.9}s\n", .{ i, seconds, nanos });
    std.debug.print("That's {d}ns per NUID (for the global Nuid)\n", .{diff / n});
}
