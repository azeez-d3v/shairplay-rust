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

fn rtp_category(packet: &[u8]) -> &'static str {
    if packet.len() < 12 {
        "short"
    } else if packet[0] >> 6 != 2 {
        "version"
    } else if packet[0] != 0x80 {
        "header"
    } else if packet[1] & 0x7f != 96 {
        "payload_type"
    } else if packet.len() == 12 || packet[12..] == [0, 0x68, 0x34, 0] {
        "bootstrap"
    } else {
        "data"
    }
}

#[derive(Default)]
pub(crate) struct AudioProbe {
    data: u64,
    mismatch: u64,
    mismatch_family: u64,
    short: u64,
    version: u64,
    header: u64,
    payload_type: u64,
    bootstrap: u64,
    queued: u64,
    duplicate: u64,
    rejected: u64,
    control: u64,
    control_mismatch: u64,
    control_mismatch_family: u64,
    sync: u64,
    sync_accepted: u64,
    callbacks: u64,
    timed_callbacks: u64,
    io_errors: u64,
}
impl AudioProbe {
    pub(crate) fn data(
        &mut self,
        packet: &[u8],
        source_matches: bool,
        family_matches: bool,
        queued: Option<i32>,
    ) {
        if !enabled() {
            return;
        }
        self.data += 1;
        if !source_matches {
            self.mismatch += 1;
            if !family_matches {
                self.mismatch_family += 1;
            }
        }
        match rtp_category(packet) {
            "short" => self.short += 1,
            "version" => self.version += 1,
            "header" => self.header += 1,
            "payload_type" => self.payload_type += 1,
            "bootstrap" => self.bootstrap += 1,
            _ => {}
        }
        match queued {
            Some(1) => {
                self.queued += 1;
                if self.queued == 1 {
                    emit(format_args!("stage=audio_first_packet"));
                }
            }
            Some(0) if rtp_category(packet) != "bootstrap" => self.duplicate += 1,
            Some(value) if value < 0 => self.rejected += 1,
            _ => {}
        }
    }
    pub(crate) fn control(
        &mut self,
        packet: &[u8],
        sample_rate: u32,
        source_matches: bool,
        family_matches: bool,
        sync: Option<bool>,
    ) {
        if !enabled() {
            return;
        }
        self.control += 1;
        if !source_matches {
            self.control_mismatch += 1;
            if !family_matches {
                self.control_mismatch_family += 1;
            }
        }
        if let Some(accepted) = sync {
            self.sync += 1;
            if accepted {
                self.sync_accepted += 1;
            }
            if self.sync == 1 || (!accepted && self.sync - self.sync_accepted == 1) {
                emit(format_args!(
                    "stage=audio_sync_probe accepted={} bytes={} version_valid={} payload_type_valid={} sample_rate_present={}",
                    accepted,
                    packet.len(),
                    packet.first().is_some_and(|value| value >> 6 == 2),
                    packet.get(1).is_some_and(|value| value & 0x7f == 0x54),
                    sample_rate != 0
                ));
            }
        }
    }
    pub(crate) fn callback(&mut self, timed: bool) {
        if !enabled() {
            return;
        }
        self.callbacks += 1;
        self.timed_callbacks += u64::from(timed);
        if self.callbacks == 1 {
            emit(format_args!("stage=audio_first_callback timed={timed}"));
        }
    }
    pub(crate) fn io_error(&mut self) {
        self.io_errors += 1;
    }
}
impl Drop for AudioProbe {
    fn drop(&mut self) {
        emit(format_args!(
            "stage=audio_summary data={} source_mismatch={} cross_family={} short={} version={} header={} payload_type={} bootstrap={} queued={} duplicate_or_stale={} rejected={} control={} control_source_mismatch={} control_cross_family={} sync={} sync_accepted={} callbacks={} timed_callbacks={} io_errors={}",
            self.data,
            self.mismatch,
            self.mismatch_family,
            self.short,
            self.version,
            self.header,
            self.payload_type,
            self.bootstrap,
            self.queued,
            self.duplicate,
            self.rejected,
            self.control,
            self.control_mismatch,
            self.control_mismatch_family,
            self.sync,
            self.sync_accepted,
            self.callbacks,
            self.timed_callbacks,
            self.io_errors
        ));
    }
}

pub(crate) struct NtpProbe {
    pub(crate) remote_port_present: bool,
    pub(crate) sent: u64,
    pub(crate) received: u64,
    pub(crate) source_mismatch: u64,
    pub(crate) cross_family: u64,
    pub(crate) requests: u64,
    pub(crate) replies: u64,
    pub(crate) responses: u64,
    pub(crate) matched: u64,
    pub(crate) valid: u64,
    pub(crate) io_errors: u64,
}
impl NtpProbe {
    pub(crate) fn new(remote_port_present: bool) -> Self {
        emit(format_args!(
            "stage=ntp_started remote_port_present={remote_port_present}"
        ));
        Self {
            remote_port_present,
            sent: 0,
            received: 0,
            source_mismatch: 0,
            cross_family: 0,
            requests: 0,
            replies: 0,
            responses: 0,
            matched: 0,
            valid: 0,
            io_errors: 0,
        }
    }
}
impl Drop for NtpProbe {
    fn drop(&mut self) {
        emit(format_args!(
            "stage=ntp_summary remote_port_present={} sent={} received={} source_mismatch={} cross_family={} requests={} replies={} responses={} matched={} valid={} io_errors={}",
            self.remote_port_present,
            self.sent,
            self.received,
            self.source_mismatch,
            self.cross_family,
            self.requests,
            self.replies,
            self.responses,
            self.matched,
            self.valid,
            self.io_errors
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rtp_categories_are_bounded_and_do_not_expose_packet_content() {
        assert_eq!(rtp_category(&[]), "short");
        let mut packet = [0u8; 16];
        assert_eq!(rtp_category(&packet), "version");
        packet[0] = 0x90;
        assert_eq!(rtp_category(&packet), "header");
        packet[0] = 0x80;
        assert_eq!(rtp_category(&packet), "payload_type");
        packet[1] = 0x60;
        assert_eq!(rtp_category(&packet[..12]), "bootstrap");
        packet[12..].copy_from_slice(&[0, 0x68, 0x34, 0]);
        assert_eq!(rtp_category(&packet), "bootstrap");
        packet[12..].fill(0xaa);
        assert_eq!(rtp_category(&packet), "data");
    }
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
