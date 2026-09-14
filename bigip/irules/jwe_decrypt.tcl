#
# jwe_decrypt.tcl — decrypt a JWE request body so Advanced WAF can inspect it.
#
# Attached to:  vs_jwe_ingress  (10.1.10.40:443)   NO ASM policy on this VS
# Chains to:    vs_waf_internal (10.1.10.241:8080) ASM policy lives there
#
# WHY THE CHAIN
# -------------
# ASM could be attached to this same VS, but then ASM's inspection would share a
# flow with an HTTP::collect / HTTP::payload replace sequence. K000158872
# (Dec 2025) covers exactly that interaction and is behind MyF5 auth, so rather
# than bet on it, this rule decrypts on a WAF-free VS and hands a clean,
# already-plaintext request to a second VS that does nothing but WAF. ASM then
# sees an ordinary JSON POST with no iRule payload manipulation in its flow.
#
# bigip/irules/jwe_single.tcl is the single-VS variant, kept so the lab can
# MEASURE that interaction instead of assuming it. See docs/FINDINGS.md.
#
# TWO THINGS THAT LOOK OPTIONAL AND ARE NOT
# -----------------------------------------
# 1. Content-Type must be rewritten to application/json. ASM selects a JSON
#    content profile by matching the Content-Type header value (typically
#    *json*). Leave it as application/jose and ASM never applies the JSON
#    profile, so there is no deep parameter inspection — the payload is
#    plaintext but unexamined, which looks like success and is not.
# 2. The size guard runs BEFORE HTTP::collect. ILX::call cannot carry more than
#    65 536 bytes, so an oversize body must be decided on, not discovered
#    mid-call. Fail open here and you have rebuilt the very bypass this rule
#    exists to close.
#
when RULE_INIT {
    # ILX::call transport ceiling. Not a tunable — raising it does not work.
    set static::JWE_MAX_PAYLOAD 65536

    # closed = reject what cannot be decrypted and therefore cannot be inspected.
    # open   = forward it undecrypted. That is a deliberate WAF bypass and exists
    #          only so run_matrix.py can demonstrate the difference.
    set static::JWE_FAIL_MODE "closed"

    # MUST match the AS3 tenant/application that owns the inner VS
    # (bigip/as3/waf-jwe-declaration.json -> jwe_lab.jwe_app.vs_waf_internal).
    # Change both together, or the chain silently has nowhere to go.
    set static::JWE_WAF_VS  "/jwe_lab/jwe_app/vs_waf_internal"

    set static::JWE_PLUGIN  "jwe_decrypt_plugin"
    set static::JWE_EXT     "jwe_decrypt_ext"

    # 0 = log rejections only. 1 = also log kid and sizes per request.
    set static::JWE_DEBUG 0
}

when HTTP_REQUEST {
    set jwe_reqid "[TCP::client_addr]:[TCP::client_port]-[clock clicks]"
    set jwe_active 0

    set ct [string tolower [HTTP::header value "Content-Type"]]

    # Target the WAF VS for every request, decrypted or not, so the inner VS is
    # the single inspection point. Chosen here rather than in HTTP_REQUEST_DATA
    # because selecting a target once, early, keeps the data-path simple; a
    # later HTTP::respond still wins over it when we fail closed.
    virtual $static::JWE_WAF_VS

    if { not ($ct starts_with "application/jose") } {
        # Plaintext request: nothing to do, the WAF VS inspects it natively.
        return
    }

    set jwe_active 1
    HTTP::header insert "X-Original-Content-Type" [HTTP::header value "Content-Type"]
    HTTP::header insert "X-JWE-Req-Id" $jwe_reqid

    # Chunked bodies have no Content-Length, so the size guard cannot run and
    # the transport cap cannot be honoured. Rejected explicitly — silently
    # collecting an unbounded body is how this becomes a bypass.
    if { not [HTTP::header exists "Content-Length"] } {
        log local0.warn "JWE reject reqid=$jwe_reqid reason=no_content_length \
            (chunked bodies are not supported; see docs/LIMITATIONS.md)"
        HTTP::respond 411 content \
            "{\"error\":\"length_required\",\"detail\":\"JWE body requires Content-Length\"}" \
            "Content-Type" "application/json"
        return
    }

    set clen [HTTP::header value "Content-Length"]

    if { $clen == 0 } {
        log local0.warn "JWE reject reqid=$jwe_reqid reason=empty_body"
        HTTP::respond 400 content \
            "{\"error\":\"empty_body\",\"detail\":\"application/jose with no body\"}" \
            "Content-Type" "application/json"
        return
    }

    if { $clen > $static::JWE_MAX_PAYLOAD } {
        # THE decision that fail_mode governs. Oversize means uninspectable.
        if { $static::JWE_FAIL_MODE eq "closed" } {
            log local0.warn "JWE reject reqid=$jwe_reqid reason=oversize \
                len=$clen cap=$static::JWE_MAX_PAYLOAD"
            HTTP::respond 413 content \
                "{\"error\":\"payload_too_large\",\"detail\":\"JWE exceeds decryptable size\"}" \
                "Content-Type" "application/json"
        } else {
            log local0.crit "JWE BYPASS reqid=$jwe_reqid reason=oversize_fail_open \
                len=$clen — forwarding UNDECRYPTED, WAF cannot inspect this body"
        }
        return
    }

    HTTP::collect $clen
}

when HTTP_REQUEST_DATA {
    if { !$jwe_active } {
        HTTP::release
        return
    }

    set token [string trim [HTTP::payload]]
    set rc ""

    if { [catch {
        set jwe_handle [ILX::init $static::JWE_PLUGIN $static::JWE_EXT]
        set rc [ILX::call $jwe_handle "decrypt" $token]
    } ilxerr] } {
        # Plugin down, not started, or timed out. Uninspectable either way.
        if { $static::JWE_FAIL_MODE eq "closed" } {
            log local0.err "JWE reject reqid=$jwe_reqid reason=ilx_error detail=$ilxerr"
            HTTP::respond 502 content \
                "{\"error\":\"decrypt_unavailable\",\"detail\":\"JWE service error\"}" \
                "Content-Type" "application/json"
            return
        }
        log local0.crit "JWE BYPASS reqid=$jwe_reqid reason=ilx_error_fail_open detail=$ilxerr"
        HTTP::release
        return
    }

    # Wire format is pipe-delimited because iRules TCL has no JSON parser:
    #   OK|<kid>|<base64 plaintext>      ERR|<reason>|<detail>
    set parts [split $rc "|"]
    set status [lindex $parts 0]

    if { $status ne "OK" } {
        set reason [lindex $parts 1]
        set detail [lindex $parts 2]
        if { $static::JWE_FAIL_MODE eq "closed" } {
            log local0.warn "JWE reject reqid=$jwe_reqid reason=$reason detail=$detail"
            HTTP::respond 400 content \
                "{\"error\":\"jwe_invalid\",\"reason\":\"$reason\"}" \
                "Content-Type" "application/json"
            return
        }
        log local0.crit "JWE BYPASS reqid=$jwe_reqid reason=${reason}_fail_open \
            — forwarding UNDECRYPTED, WAF cannot inspect this body"
        HTTP::release
        return
    }

    set kid [lindex $parts 1]
    set plaintext [b64decode [lindex $parts 2]]

    # Swap ciphertext for plaintext. Offset 0, length = everything collected.
    HTTP::payload replace 0 [HTTP::payload length] $plaintext
    HTTP::header replace "Content-Length" [string length $plaintext]

    # Non-negotiable (see header comment #1): without this, ASM does not select
    # a JSON profile and performs no deep inspection of the now-plaintext body.
    HTTP::header replace "Content-Type" "application/json"

    HTTP::header insert "X-JWE-Decrypted" "true"
    HTTP::header insert "X-JWE-Kid" $kid

    if { $static::JWE_DEBUG } {
        log local0.info "JWE ok reqid=$jwe_reqid kid=$kid \
            ct_in=[HTTP::header value X-Original-Content-Type] \
            pt_len=[string length $plaintext]"
    }

    HTTP::release
}
