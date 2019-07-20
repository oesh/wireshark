--
-- Tests multiple repeated calls to a dissector.
--

-- grab passed-in arguments
local script_args = { ... }
local disable_accept_test = script_args[1] == 'disable_accept_test'

local function fail(msg)
    -- Lua errors are not visible in the tshark summary output, print the
    -- message as workaround.
    print(msg)
    error(msg)
end

local count = 0

local rejecting_proto = Proto("test.reject", "Rejects data")
function rejecting_proto.dissector(tvb, pinfo, tree)
    -- Note: does not use 'tree' and rejects data.
    count = count + 1
    return 0
end

local disable_proto = Proto("test.disable", "Disable this Test Protocol")
function disable_proto.dissector(tvb, pinfo, tree)
    count = count + 1
end

local accept_proto = Proto("test.accept", "Useless Test Protocol")
function accept_proto.dissector(tvb, pinfo, tree)
    -- Note: does not use 'tree', but accepts data (returning nil implies that)
    count = count + 1
end

local test_proto = Proto("test", "Test Protocol")
function test_proto.dissector(tvb, pinfo, tree)
    local ROUNDS = 10000

    print("Running test.reject")
    count = 0
    for i=1, ROUNDS do
        Dissector.get("test.reject"):call(tvb, pinfo, tree)
    end
    if count ~= ROUNDS then
        fail(string.format('test.reject: expected %s, got %s', ROUNDS, count))
    end

    print("Running test.disable")
    count = 0
    local ROUNDS = 10000
    for i=1, ROUNDS do
        Dissector.get("test.disable"):call(tvb, pinfo, tree)
    end
    if count ~= 0 then
        fail('test.disable: expected dissector to be disabled')
    end

    -- FIXME should dissectors which add no tree items be treated specially, and
    -- handled as if no dissector was called at all?
    -- See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=15917
    if not disable_accept_test then
        print("Running test.accept")
        count = 0
        for i=1, ROUNDS do
            Dissector.get("test.accept"):call(tvb, pinfo, tree)
        end
        if count ~= ROUNDS then
            fail(string.format('test.accept: expected %s, got %s', ROUNDS, count))
        end
    end

    print("All tests passed!")
end

DissectorTable.get("udp.port"):add(123, test_proto)
