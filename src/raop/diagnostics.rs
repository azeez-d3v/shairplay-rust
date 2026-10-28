//! Explicitly opted-in lifecycle diagnostics containing categories, never peer data.

use std::io::Write;

fn enabled() -> bool {
    std::env::var_os("XSTUDIO_AIRPLAY_DIAGNOSTICS").is_some_and(|value| value == "1")
}

pub(crate) fn emit(message: std::fmt::Arguments<'_>) {
    if enabled() {
        let _ = writeln!(std::io::stderr().lock(), "[Shairplay/Diagnostic] {message}");
    }
}

pub(crate) fn rtsp_response(
    method: &str,
    route: &str,
    body: Option<&[u8]>,
    status: u16,
    disconnect: bool,
) {
    if !enabled() {
        return;
    }
    let mask = if method == "TEARDOWN" {
        teardown_mask(body)
    } else {
        0
    };
    emit(format_args!(
        "stage=rtsp_response method={} route={} status={} disconnect={} teardown_audio={} teardown_video={} teardown_buffered={} teardown_remote={} teardown_other={}",
        method_category(method),
        route_category(route),
        status,
        disconnect,
        mask & 1 != 0,
        mask & 2 != 0,
        mask & 4 != 0,
        mask & 8 != 0,
        mask & 16 != 0,
    ));
}

fn method_category(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "OPTIONS" => "OPTIONS",
        "SETUP" => "SETUP",
        "RECORD" => "RECORD",
        "ANNOUNCE" => "ANNOUNCE",
        "SET_PARAMETER" => "SET_PARAMETER",
        "GET_PARAMETER" => "GET_PARAMETER",
        "FLUSH" => "FLUSH",
        "TEARDOWN" => "TEARDOWN",
        _ => "other",
    }
}
fn route_category(route: &str) -> &'static str {
    match route {
        "/info" => "info",
        "/feedback" => "feedback",
        "/command" => "command",
        "/audioMode" => "audio_mode",
        "/pair-setup" => "pair_setup",
        "/pair-setup-pin" => "pin_setup",
        "/pair-pin-start" => "pin_start",
        "/pair-verify" => "pair_verify",
        "/fp-setup" => "fairplay",
        "/" | "*" => "session",
        _ => "other",
    }
}
fn teardown_mask(body: Option<&[u8]>) -> u8 {
    let Some(body) = body.filter(|body| !body.is_empty()) else {
        return 0;
    };
    let Ok(value) = plist::from_bytes::<plist::Value>(body) else {
        return 16;
    };
    let Some(streams) = value
        .as_dictionary()
        .and_then(|dict| dict.get("streams"))
        .and_then(plist::Value::as_array)
    else {
        return 0;
    };
    streams.iter().fold(0, |mask, stream| {
        mask | match stream
            .as_dictionary()
            .and_then(|dict| dict.get("type"))
            .and_then(plist::Value::as_unsigned_integer)
        {
            Some(96) => 1,
            Some(110) => 2,
            Some(103) => 4,
            Some(130) => 8,
            _ => 16,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn categories_do_not_echo_untrusted_input() {
        assert_eq!(method_category("TEARDOWN"), "TEARDOWN");
        assert_eq!(method_category("GET\nsecret"), "other");
        assert_eq!(route_category("/feedback"), "feedback");
        assert_eq!(route_category("/info?token=secret"), "other");
        assert_eq!(route_category("rtsp://private-host/secret"), "other");
    }
    #[test]
    fn teardown_reports_only_known_type_bits_or_other() {
        let stream = |kind: u64| {
            plist::Value::Dictionary(plist::Dictionary::from_iter([(
                "type",
                plist::Value::Integer(kind.into()),
            )]))
        };
        let body = plist::Dictionary::from_iter([(
            "streams",
            plist::Value::Array(vec![
                stream(96),
                stream(110),
                stream(103),
                stream(130),
                stream(999),
            ]),
        )]);
        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &body).unwrap();
        assert_eq!(teardown_mask(Some(&bytes)), 31);
        assert_eq!(teardown_mask(None), 0);
        assert_eq!(teardown_mask(Some(b"private malformed content")), 16);
    }
}
