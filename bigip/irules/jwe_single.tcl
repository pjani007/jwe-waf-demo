#
# jwe_single.tcl — EXPERIMENTAL single-VS variant.
#
# Attached to:  vs_jwe_single (10.1.10.43:443) WITH the ASM policy on the SAME VS.
#
# This exists to answer one question empirically rather than by assumption:
# does ASM inspect the payload as rewritten by HTTP::payload replace, when the
# collect/replace sequence happens in ASM's own flow?
#
# K000158872 (Dec 2025) documents an interaction between iRules using
# HTTP::collect and ASM payload inspection, and is behind MyF5 auth — so this
# lab measures the behaviour instead of trusting either answer. The production
# path is bigip/irules/jwe_decrypt.tcl, which chains to a separate WAF VS and
# sidesteps the question entirely.
#
# EXPECTED OUTCOMES, both informative:
#   attack in JWE -> BLOCKED  => ASM sees rewritten payload; single VS is viable
#   attack in JWE -> 200      => ASM inspected the ciphertext; the chain is REQUIRED
#
# Record whichever you observe in docs/FINDINGS.md.
#
when RULE_INIT {
    set static::JWES_MAX_PAYLOAD 65536
    set static::JWES_PLUGIN "jwe_decrypt_plugin"
    set static::JWES_EXT    "jwe_decrypt_ext"
}

when HTTP_REQUEST {
    set jwes_reqid "[TCP::client_addr]:[TCP::client_port]-[clock clicks]"
    set jwes_active 0

    set ct [string tolower [HTTP::header value "Content-Type"]]
    if { not ($ct starts_with "application/jose") } { return }

    if { not [HTTP::header exists "Content-Length"] } {
        HTTP::respond 411 content "{\"error\":\"length_required\"}" \
            "Content-Type" "application/json"
        return
    }

    set clen [HTTP::header value "Content-Length"]
    if { $clen == 0 || $clen > $static::JWES_MAX_PAYLOAD } {
        HTTP::respond 413 content "{\"error\":\"payload_too_large_or_empty\"}" \
            "Content-Type" "application/json"
        return
    }

    set jwes_active 1
    HTTP::header insert "X-JWE-Req-Id" $jwes_reqid
    HTTP::collect $clen
}

when HTTP_REQUEST_DATA {
    if { !$jwes_active } {
        HTTP::release
        return
    }

    set rc ""
    if { [catch {
        set h [ILX::init $static::JWES_PLUGIN $static::JWES_EXT]
        set rc [ILX::call $h "decrypt" [string trim [HTTP::payload]]]
    } err] } {
        log local0.err "JWE-single reject reqid=$jwes_reqid reason=ilx_error detail=$err"
        HTTP::respond 502 content "{\"error\":\"decrypt_unavailable\"}" \
            "Content-Type" "application/json"
        return
    }

    set parts [split $rc "|"]
    if { [lindex $parts 0] ne "OK" } {
        log local0.warn "JWE-single reject reqid=$jwes_reqid reason=[lindex $parts 1]"
        HTTP::respond 400 content "{\"error\":\"jwe_invalid\",\"reason\":\"[lindex $parts 1]\"}" \
            "Content-Type" "application/json"
        return
    }

    set plaintext [b64decode [lindex $parts 2]]
    HTTP::payload replace 0 [HTTP::payload length] $plaintext
    HTTP::header replace "Content-Length" [string length $plaintext]
    HTTP::header replace "Content-Type" "application/json"
    HTTP::header insert "X-JWE-Decrypted" "true"
    HTTP::header insert "X-JWE-Kid" [lindex $parts 1]

    HTTP::release
}
