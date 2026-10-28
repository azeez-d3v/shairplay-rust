//! NTP timing responder for AirPlay legacy connections.
//!
//! Sends timing requests to the iPhone and responds to incoming
//! timing requests. Required for legacy (non-PTP) AirPlay connections.

/// Seconds between the NTP epoch (1900-01-01) and the UNIX epoch (1970-01-01).
const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 0x83AA_7E80; // 2_208_988_800

/// Convert boot-relative Q32.32 to nanoseconds without floating point.
pub(crate) fn video_time(raw: u64) -> Option<u64> {
    Some(((u128::from(raw) * 1_000_000_000) >> 32) as u64)
}

#[derive(Default)]
pub(crate) struct SenderClock {
    anchor: Option<(u32, u64)>,
    receiver_offset_ns: Option<i64>,
}
impl SenderClock {
    pub(crate) fn reset(&mut self) {
        self.anchor = None;
    }
    pub(crate) fn audio_time(&self, timestamp: u32, rate: u32) -> Option<u64> {
        let (rtp, ns) = self.anchor?;
        if rate == 0 {
            return None;
        }
        let delta = timestamp.wrapping_sub(rtp) as i32 as i128;
        u64::try_from(i128::from(ns) + delta * 1_000_000_000 / i128::from(rate)).ok()
    }
    pub(crate) fn sync(&mut self, packet: &[u8], rate: u32) -> bool {
        if packet.len() != 20 || packet[0] >> 6 != 2 || packet[1] & 0x7f != 0x54 || rate == 0 {
            return false;
        }
        let rtp = u32::from_be_bytes(packet[4..8].try_into().unwrap());
        let raw = u64::from_be_bytes(packet[8..16].try_into().unwrap());
        let boot_seconds = ((raw >> 32) as u32).wrapping_sub(NTP_UNIX_EPOCH_OFFSET_SECS as u32);
        let ns = video_time((u64::from(boot_seconds) << 32) | (raw & 0xffff_ffff)).unwrap();
        // Reject anchors that would independently jump audio relative to video.
        if self
            .audio_time(rtp, rate)
            .is_some_and(|predicted| predicted.abs_diff(ns) > 100_000_000)
        {
            return false;
        }
        self.anchor = Some((rtp, ns));
        true
    }
}

pub(crate) fn parse_flush_sequence(info: &str) -> Option<i32> {
    info.split(';')
        .find_map(|field| field.trim().strip_prefix("seq="))
        .and_then(|s| s.parse::<u16>().ok())
        .map(i32::from)
}

// Timing estimates are diagnostics/validation only: the host maps one shared sender clock.
fn timing_estimate(packet: &[u8], origin: u64, received: u64) -> Option<i64> {
    if packet.len() != 32 || packet[0] >> 6 != 2 || packet[1] & 0x7f != 0x53 {
        return None;
    }
    let read = |i| u64::from_be_bytes(packet[i..i + 8].try_into().unwrap());
    if read(8) != origin {
        return None;
    }
    let t2 = read(16);
    let t3 = read(24);
    let diff =
        |a: u64, b: u64| i128::from(a.wrapping_sub(b) as i64) * 1_000_000_000 / (1i128 << 32);
    if (t3.wrapping_sub(t2) as i64) < 0 {
        return None;
    }
    let processing = diff(t3, t2);
    let delay = diff(received, origin) - processing;
    if processing < 0 || !(0..=200_000_000).contains(&delay) {
        return None;
    }
    i64::try_from(diff(t2, origin).midpoint(diff(t3, received))).ok()
}

/// timing requests and sends periodic keepalives. Required for legacy AirPlay
/// connections where the iPhone expects NTP sync before streaming audio.
pub(crate) fn spawn_ntp_responder(
    tsock: tokio::net::UdpSocket,
    remote_timing: std::net::SocketAddr,
    media: std::sync::Arc<super::media::MediaContext>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut probe = super::diagnostics::NtpProbe::new(remote_timing.port() != 0);
        let mut buf = [0u8; 128];
        let mut pending = std::collections::VecDeque::with_capacity(3);

        let ntp_now = || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = (now.as_secs() + NTP_UNIX_EPOCH_OFFSET_SECS) as u32;
            let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;
            (secs, frac as u32)
        };

        let put_ntp = |buf: &mut [u8], off: usize, secs: u32, frac: u32| {
            buf[off..off + 4].copy_from_slice(&secs.to_be_bytes());
            buf[off + 4..off + 8].copy_from_slice(&frac.to_be_bytes());
        };

        // Send initial timing requests to iPhone
        if remote_timing.port() > 0 {
            tracing::debug!(%remote_timing, "NTP: sending initial timing requests");
            for _ in 0..3 {
                let mut req = [0u8; 32];
                req[0] = 0x80;
                req[1] = 0xd2;
                req[2] = 0x00;
                req[3] = 0x07;
                let (s, f) = ntp_now();
                put_ntp(&mut req, 24, s, f);
                if pending.len() == 3 {
                    pending.pop_front();
                }
                pending.push_back((u64::from(s) << 32) | u64::from(f));
                if tsock.send_to(&req, remote_timing).await.is_ok() {
                    probe.sent += 1;
                } else {
                    probe.io_errors += 1;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        loop {
            let timeout = tokio::time::sleep(std::time::Duration::from_secs(3));
            tokio::select! {
                result = tsock.recv_from(&mut buf) => {
                    if let Ok((_,addr)) = &result {
                        probe.received += 1;
                        if *addr != remote_timing { probe.source_mismatch += 1; }
                        if addr.is_ipv6() != remote_timing.is_ipv6() { probe.cross_family += 1; }
                    }
                    match result {
                        Ok((len, addr)) if addr == remote_timing && len == 32 && buf[0] >> 6 == 2 && buf[1] & 0x7f == 0x52 => {
                            probe.requests += 1;
                            // Timing request — send response
                            let mut resp = [0u8; 32];
                            resp[..32].copy_from_slice(&buf[..32]);
                            resp[1] = 0xd3;
                            resp[8..16].copy_from_slice(&buf[24..32]);
                            let (s, f) = ntp_now();
                            put_ntp(&mut resp, 16, s, f);
                            put_ntp(&mut resp, 24, s, f);
                            if tsock.send_to(&resp, addr).await.is_ok() { probe.replies += 1; } else { probe.io_errors += 1; }
                        }
                        Ok((32, addr)) if addr == remote_timing && buf[1] & 0x7f == 0x53 => {
                            probe.responses += 1;
                            let origin = u64::from_be_bytes(buf[8..16].try_into().unwrap());
                            if let Some(index) = pending.iter().position(|request| *request == origin) {
                                probe.matched += 1;
                                pending.remove(index);
                                let (s,f) = ntp_now();
                                if let Some(offset) = timing_estimate(&buf[..32], origin, (u64::from(s)<<32)|u64::from(f)) {
                                    probe.valid += 1;
                                    let mut clock = media.clock.lock().unwrap_or_else(|e|e.into_inner());
                                    if clock.receiver_offset_ns.is_none_or(|previous| previous.abs_diff(offset)<20_000_000) {
                                        clock.receiver_offset_ns=Some(offset);
                                    }
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(_) => { probe.io_errors += 1; break; },
                    }
                }
                _ = timeout => {
                    if remote_timing.port() > 0 {
                        let mut req = [0u8; 32];
                        req[0] = 0x80;
                        req[1] = 0xd2;
                        req[2] = 0x00;
                        req[3] = 0x07;
                        let (s, f) = ntp_now();
                        put_ntp(&mut req, 24, s, f);
                        if pending.len() == 3 { pending.pop_front(); }
                        pending.push_back((u64::from(s)<<32)|u64::from(f));
                        if tsock.send_to(&req, remote_timing).await.is_ok() { probe.sent += 1; } else { probe.io_errors += 1; }
                    }
                }
            }
        }
    })
}
#[cfg(test)]
mod native_clock_tests {
    use super::*;
    #[test]
    fn sync_anchor_converts_epoch_and_wrap_at_native_rate() {
        let mut c = SenderClock::default();
        assert_eq!(c.audio_time(10, 48000), None);
        let mut p = [0u8; 20];
        p[0] = 0x80;
        p[1] = 0xd4;
        p[4..8].copy_from_slice(&(u32::MAX - 47999).to_be_bytes());
        p[8..16].copy_from_slice(&((2_208_988_800u64 + 12) << 32).to_be_bytes());
        assert!(c.sync(&p, 48000));
        assert_eq!(c.audio_time(0, 48000), Some(13_000_000_000));
        assert_eq!(video_time(13u64 << 32), Some(13_000_000_000));
        assert!(!c.sync(&p[..19], 48000));
        p[8..16].copy_from_slice(&((2_208_988_800u64 + 100) << 32).to_be_bytes());
        assert!(!c.sync(&p, 48000));
    }
    #[test]
    fn flush_parser_accepts_multiple_fields_and_rejects_overflow() {
        assert_eq!(parse_flush_sequence("seq=65535;rtptime=300"), Some(65535));
        assert_eq!(parse_flush_sequence("rtptime=300; seq=4"), Some(4));
        assert_eq!(parse_flush_sequence("seq=65536"), None);
    }
}

#[cfg(test)]
mod timing_response_tests {
    use super::*;
    #[test]
    fn timing_response_requires_origin_and_rejects_slow_or_backwards_peer() {
        let mut p = [0u8; 32];
        p[0] = 0x80;
        p[1] = 0xd3;
        let t1 = 100u64 << 32;
        let t2 = t1 + (1u64 << 30);
        let t3 = t2 + (1u64 << 26);
        let t4 = t1 + (1u64 << 27);
        p[8..16].copy_from_slice(&t1.to_be_bytes());
        p[16..24].copy_from_slice(&t2.to_be_bytes());
        p[24..32].copy_from_slice(&t3.to_be_bytes());
        assert!(timing_estimate(&p, t1, t4).is_some());
        assert!(timing_estimate(&p, t1 + 1, t4).is_none());
        assert!(timing_estimate(&p, t1, t4 + (1u64 << 32)).is_none());
        p[24..32].copy_from_slice(&(t2 - 1).to_be_bytes());
        assert!(timing_estimate(&p, t1, t4).is_none());
    }
}
