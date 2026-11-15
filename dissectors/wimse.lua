-- dissectors/wimse.lua
-- Wireshark / tshark Lua post-dissector for IETF 127 WIMSE + OAuth Agent Call-Chain captures.
--
-- Usage in Wireshark GUI:
--   wireshark -X lua_script:dissectors/wimse.lua validation/bundle-inbound/inbound/capture.pcap
--
-- Usage in tshark CLI:
--   tshark -X lua_script:dissectors/wimse.lua -r validation/bundle-inbound/inbound/capture.pcap -Y "wimse.test_case == \"A4\"" -V

local wimse_proto = Proto("wimse", "IETF WIMSE & OAuth Agent Call Chain")

-- Filterable fields
local f_test_case   = ProtoField.string("wimse.test_case", "X-Test-Case")
local f_wit_raw     = ProtoField.string("wimse.wit.raw", "WIT Raw JWT")
local f_wit_header  = ProtoField.string("wimse.wit.header", "WIT Header JSON")
local f_wit_payload = ProtoField.string("wimse.wit.payload", "WIT Payload JSON")
local f_wit_typ     = ProtoField.string("wimse.wit.typ", "WIT typ")
local f_wit_alg     = ProtoField.string("wimse.wit.alg", "WIT alg")
local f_wit_iss     = ProtoField.string("wimse.wit.iss", "WIT Issuer (iss)")
local f_wit_sub     = ProtoField.string("wimse.wit.sub", "WIT Workload ID (sub)")
local f_wit_jti     = ProtoField.string("wimse.wit.jti", "WIT Token ID (jti)")
local f_wit_cnf_alg = ProtoField.string("wimse.wit.cnf_alg", "WIT PoP Key Alg (cnf.jwk.alg)")

local f_wpt_header  = ProtoField.string("wimse.wpt.header", "WPT Header JSON")
local f_wpt_payload = ProtoField.string("wimse.wpt.payload", "WPT Payload JSON")
local f_wpt_typ     = ProtoField.string("wimse.wpt.typ", "WPT typ")
local f_wpt_alg     = ProtoField.string("wimse.wpt.alg", "WPT alg")
local f_wpt_aud     = ProtoField.string("wimse.wpt.aud", "WPT Audience (aud)")
local f_wpt_wth     = ProtoField.string("wimse.wpt.wth", "WPT WIT Hash (wth)")
local f_wpt_tth     = ProtoField.string("wimse.wpt.tth", "WPT Txn-Token Hash (tth)")

local f_txn_header  = ProtoField.string("wimse.txn.header", "Txn-Token Header JSON")
local f_txn_payload = ProtoField.string("wimse.txn.payload", "Txn-Token Payload JSON")
local f_txn_id      = ProtoField.string("wimse.txn.id", "Transaction ID (txn)")
local f_txn_sub     = ProtoField.string("wimse.txn.sub", "Subject (sub)")
local f_txn_aud     = ProtoField.string("wimse.txn.aud", "Txn-Token Audience (aud)")
local f_txn_scope   = ProtoField.string("wimse.txn.scope", "Txn-Token Scope (scope)")
local f_txn_req_wl  = ProtoField.string("wimse.txn.req_wl", "Requesting Workload (req_wl)")

local f_at_header   = ProtoField.string("wimse.at.header", "Access Token Header JSON")
local f_at_payload  = ProtoField.string("wimse.at.payload", "Access Token Payload JSON")
local f_at_typ      = ProtoField.string("wimse.at.typ", "Access Token typ")
local f_at_iss      = ProtoField.string("wimse.at.iss", "Access Token Issuer (iss)")
local f_at_aud      = ProtoField.string("wimse.at.aud", "Access Token Audience (aud)")
local f_at_scope    = ProtoField.string("wimse.at.scope", "Access Token Scope (scope)")

local f_sig_input   = ProtoField.string("wimse.sig.input", "RFC 9421 Signature-Input")
local f_sig_tag     = ProtoField.string("wimse.sig.tag", "RFC 9421 Signature Tag")
local f_sig_aud     = ProtoField.string("wimse.sig.wimse_aud", "RFC 9421 wimse-aud")
local f_sig_nonce   = ProtoField.string("wimse.sig.nonce", "RFC 9421 Nonce")

local f_www_auth    = ProtoField.string("wimse.www_authenticate", "WWW-Authenticate Challenge")

wimse_proto.fields = {
    f_test_case,
    f_wit_raw, f_wit_header, f_wit_payload, f_wit_typ, f_wit_alg, f_wit_iss, f_wit_sub, f_wit_jti, f_wit_cnf_alg,
    f_wpt_header, f_wpt_payload, f_wpt_typ, f_wpt_alg, f_wpt_aud, f_wpt_wth, f_wpt_tth,
    f_txn_header, f_txn_payload, f_txn_id, f_txn_sub, f_txn_aud, f_txn_scope, f_txn_req_wl,
    f_at_header, f_at_payload, f_at_typ, f_at_iss, f_at_aud, f_at_scope,
    f_sig_input, f_sig_tag, f_sig_aud, f_sig_nonce,
    f_www_auth
}

-- Auto-bind WIMSE interop ports (5050..5064) to HTTP so manual "Decode As" is not needed
local tcp_port_table = DissectorTable.get("tcp.port")
local http_dissector = Dissector.get("http-over-tcp") or Dissector.get("http")
if tcp_port_table and http_dissector then
    for _, port in ipairs({5050, 5051, 5052, 5060, 5061, 5062, 5063, 5064, 47999}) do
        tcp_port_table:add(port, http_dissector)
    end
end

local http_request_F  = Field.new("http.request")
local http_response_F = Field.new("http.response")
local http_headers_F  = Field.new("http.request.line")
local http_resp_hdr_F = Field.new("http.response.line")

-- Base64url decoder in pure Lua
local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
local b64lookup = {}
for i = 1, #b64chars do
    b64lookup[b64chars:sub(i, i)] = i - 1
end
b64lookup["+"] = 62
b64lookup["/"] = 63

local function b64url_decode(input)
    if not input then return nil end
    input = input:gsub("[^A-Za-z0-9%-%_%+%/]", "")
    local out = {}
    local n = #input
    local i = 1
    while i <= n do
        local c1 = b64lookup[input:sub(i, i)] or 0
        local c2 = b64lookup[input:sub(i + 1, i + 1)] or 0
        local c3 = (i + 2 <= n) and b64lookup[input:sub(i + 2, i + 2)] or nil
        local c4 = (i + 3 <= n) and b64lookup[input:sub(i + 3, i + 3)] or nil

        local b1 = bit.bor(bit.lshift(c1, 2), bit.rshift(c2, 4))
        table.insert(out, string.char(b1))
        if c3 ~= nil then
            local b2 = bit.band(bit.bor(bit.lshift(c2, 4), bit.rshift(c3, 2)), 0xFF)
            table.insert(out, string.char(b2))
            if c4 ~= nil then
                local b3 = bit.band(bit.bor(bit.lshift(c3, 6), c4), 0xFF)
                table.insert(out, string.char(b3))
            end
        end
        i = i + 4
    end
    return table.concat(out)
end

local function json_str_field(json_text, key)
    if not json_text then return nil end
    local pat = '"' .. key .. '"%s*:%s*"([^"]*)"'
    return json_text:match(pat)
end

local function split_jwt(jwt_str)
    if not jwt_str then return nil, nil end
    local h_b64, p_b64 = jwt_str:match("^([A-Za-z0-9%-%_]+)%.([A-Za-z0-9%-%_]+)%.")
    if not h_b64 or not p_b64 then return nil, nil end
    return b64url_decode(h_b64), b64url_decode(p_b64)
end

function wimse_proto.dissector(tvb, pinfo, tree)
    local is_req  = http_request_F()
    local is_resp = http_response_F()
    if not is_req and not is_resp then return end

    local lines = {}
    if is_req then
        for _, f in ipairs({http_headers_F()}) do
            table.insert(lines, tostring(f))
        end
    end
    if is_resp then
        for _, f in ipairs({http_resp_hdr_F()}) do
            table.insert(lines, tostring(f))
        end
    end
    if #lines == 0 then return end

    local subtree = nil
    local function ensure_tree()
        if not subtree then
            subtree = tree:add(wimse_proto, "IETF WIMSE & OAuth Agent Call Chain")
        end
        return subtree
    end

    for _, raw_line in ipairs(lines) do
        local line = raw_line:gsub("[\r\n]+$", "")
        local name, val = line:match("^([^:]+):%s*(.*)$")
        if name and val then
            local lname = name:lower()

            if lname == "x-test-case" then
                ensure_tree():add(f_test_case, val)
                pinfo.cols.info:append(" [Case: " .. val .. "]")

            elseif lname == "workload-identity-token" then
                local t = ensure_tree():add(wimse_proto, "Workload-Identity-Token (WIT)")
                t:add(f_wit_raw, val)
                local hdr, pay = split_jwt(val)
                if hdr and pay then
                    t:add(f_wit_header, hdr)
                    t:add(f_wit_payload, pay)
                    local typ = json_str_field(hdr, "typ")
                    local alg = json_str_field(hdr, "alg")
                    local iss = json_str_field(pay, "iss")
                    local sub = json_str_field(pay, "sub")
                    local jti = json_str_field(pay, "jti")
                    local cnf_block = pay:match('"cnf"%s*:%s*(%b{})')
                    local cnf_alg = cnf_block and json_str_field(cnf_block, "alg") or nil
                    if typ then t:add(f_wit_typ, typ) end
                    if alg then t:add(f_wit_alg, alg) end
                    if iss then t:add(f_wit_iss, iss) end
                    if sub then t:add(f_wit_sub, sub) end
                    if jti then t:add(f_wit_jti, jti) end
                    if cnf_alg then t:add(f_wit_cnf_alg, cnf_alg) end
                end

            elseif lname == "authorization" and val:match("^[Ww][Pp][Tt]%s+") then
                local wpt_jwt = val:match("^[Ww][Pp][Tt]%s+(.+)$")
                local t = ensure_tree():add(wimse_proto, "Workload-Proof-Token (WPT)")
                local hdr, pay = split_jwt(wpt_jwt)
                if hdr and pay then
                    t:add(f_wpt_header, hdr)
                    t:add(f_wpt_payload, pay)
                    local typ = json_str_field(hdr, "typ")
                    local alg = json_str_field(hdr, "alg")
                    local aud = json_str_field(pay, "aud")
                    local wth = json_str_field(pay, "wth")
                    local tth = json_str_field(pay, "tth")
                    if typ then t:add(f_wpt_typ, typ) end
                    if alg then t:add(f_wpt_alg, alg) end
                    if aud then t:add(f_wpt_aud, aud) end
                    if wth then t:add(f_wpt_wth, wth) end
                    if tth then t:add(f_wpt_tth, tth) end
                end

            elseif lname == "authorization" and val:match("^[Bb]earer%s+") then
                local at_jwt = val:match("^[Bb]earer%s+(.+)$")
                local t = ensure_tree():add(wimse_proto, "OAuth Bearer Token (Authorization: Bearer)")
                local hdr, pay = split_jwt(at_jwt)
                if hdr and pay then
                    t:add(f_at_header, hdr)
                    t:add(f_at_payload, pay)
                    local typ   = json_str_field(hdr, "typ")
                    local iss   = json_str_field(pay, "iss")
                    local aud   = json_str_field(pay, "aud")
                    local scope = json_str_field(pay, "scope")
                    local txn   = json_str_field(pay, "txn")
                    if typ then t:add(f_at_typ, typ) end
                    if iss then t:add(f_at_iss, iss) end
                    if aud then t:add(f_at_aud, aud) end
                    if scope then t:add(f_at_scope, scope) end
                    if txn then t:add(f_txn_id, txn) end
                end

            elseif lname == "txn-token" then
                local t = ensure_tree():add(wimse_proto, "OAuth Transaction Token (Txn-Token)")
                local hdr, pay = split_jwt(val)
                if hdr and pay then
                    t:add(f_txn_header, hdr)
                    t:add(f_txn_payload, pay)
                    local txn    = json_str_field(pay, "txn")
                    local sub    = json_str_field(pay, "sub")
                    local aud    = json_str_field(pay, "aud")
                    local scope  = json_str_field(pay, "scope")
                    local req_wl = json_str_field(pay, "req_wl")
                    if txn then t:add(f_txn_id, txn) end
                    if sub then t:add(f_txn_sub, sub) end
                    if aud then t:add(f_txn_aud, aud) end
                    if scope then t:add(f_txn_scope, scope) end
                    if req_wl then t:add(f_txn_req_wl, req_wl) end
                end

            elseif lname == "signature-input" then
                local t = ensure_tree():add(wimse_proto, "RFC 9421 HTTP Message Signature")
                t:add(f_sig_input, val)
                local tag = val:match(';tag="([^"]*)"')
                local aud = val:match(';wimse%-aud="([^"]*)"')
                local nonce = val:match(';nonce="([^"]*)"')
                if tag then t:add(f_sig_tag, tag) end
                if aud then t:add(f_sig_aud, aud) end
                if nonce then t:add(f_sig_nonce, nonce) end

            elseif lname == "www-authenticate" then
                ensure_tree():add(f_www_auth, val)
            end
        end
    end
end

register_postdissector(wimse_proto)
