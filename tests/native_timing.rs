//! Native RTP metadata and encoded packet regressions.
use shairplay::raop::buffer::RaopBuffer;
fn packet(seq: u16, timestamp: u32) -> Vec<u8> {
    let mut p = vec![0x80, 96];
    p.extend(seq.to_be_bytes());
    p.extend(timestamp.to_be_bytes());
    p.extend(1u32.to_be_bytes());
    p.extend([0, 1, 0, 2]);
    p
}
#[test]
fn metadata_survives_reorder_loss_and_wrap() {
    let mut b = RaopBuffer::new_unencrypted("96 L16/48000/2", "").unwrap();
    b.queue(&packet(65535, u32::MAX), true);
    b.queue(&packet(1, 1), true);
    let f = b.dequeue_timed(true).unwrap();
    assert_eq!(
        (f.sequence, f.timestamp, f.sample_count, f.concealed),
        (65535, u32::MAX, 1, false)
    );
    let f = b.dequeue_timed(true).unwrap();
    assert_eq!(
        (f.sequence, f.timestamp, f.sample_count, f.concealed),
        (0, 0, 1, true)
    );
    assert!(f.samples.iter().all(|v| *v == 0.0));
    let f = b.dequeue_timed(true).unwrap();
    assert_eq!((f.sequence, f.timestamp), (1, 1));
}
#[test]
fn flush_does_not_reuse_previous_timestamp() {
    let mut b = RaopBuffer::new_unencrypted("96 L16/44100/2", "").unwrap();
    b.queue(&packet(1, 50), true);
    b.dequeue_timed(true).unwrap();
    b.flush(-1);
    b.queue(&packet(5, 900), true);
    assert_eq!(b.dequeue_timed(true).unwrap().timestamp, 900);
}
#[test]
fn encoded_eld_payload_is_not_misdecoded_as_alac() {
    use shairplay::{EncodedAudioFormat, WireAudioCodec};
    let f = EncodedAudioFormat {
        codec: WireAudioCodec::AacEld,
        sample_rate: 44100,
        channels: 2,
        samples_per_frame: 480,
        codec_config: vec![0xf8, 0xe8, 0x50, 0],
    };
    let mut b = RaopBuffer::new_encoded(f, None).unwrap();
    let p = packet(9, 480);
    b.queue(&p, true);
    let f = b.dequeue_timed(true).unwrap();
    assert_eq!(f.encoded, Some(&p[12..]));
    assert_eq!(f.samples, &[]);
    assert_eq!(f.sample_count, 480);
}
#[test]
fn retransmitted_packet_keeps_timestamp_and_flush_rejects_stale_sequence() {
    let mut b = RaopBuffer::new_unencrypted("96 L16/44100/2", "").unwrap();
    b.flush(12);
    assert_eq!(b.queue(&packet(11, 100), true), 0);
    b.queue(&packet(12, 101), true);
    b.queue(&packet(14, 103), true);
    assert_eq!(b.dequeue_timed(false).unwrap().timestamp, 101);
    assert!(b.dequeue_timed(false).is_none());
    b.queue(&packet(13, 102), true);
    assert_eq!(b.dequeue_timed(false).unwrap().timestamp, 102);
    assert_eq!(b.dequeue_timed(false).unwrap().timestamp, 103);
}
#[test]
fn untrusted_codec_sizes_and_unsupported_rtp_headers_are_rejected() {
    assert!(
        RaopBuffer::new_unencrypted(
            "96 AppleLossless",
            "96 4294967295 0 16 40 10 14 2 255 0 0 44100"
        )
        .is_none()
    );
    let mut b = RaopBuffer::new_unencrypted("96 L16/44100/2", "").unwrap();
    let mut p = packet(1, 1);
    p[0] = 0x90;
    assert_eq!(b.queue(&p, true), -1);
}
#[test]
fn encoded_bootstrap_packets_do_not_publish_empty_audio_or_establish_sequence() {
    use shairplay::{EncodedAudioFormat, WireAudioCodec};
    let format = EncodedAudioFormat {
        codec: WireAudioCodec::AacEld,
        sample_rate: 44100,
        channels: 2,
        samples_per_frame: 480,
        codec_config: vec![0xf8, 0xe8, 0x50, 0],
    };
    let mut b = RaopBuffer::new_encoded(format, None).unwrap();
    let mut empty = packet(200, 9000);
    empty.truncate(12);
    assert_eq!(b.queue(&empty, true), 0);
    assert!(b.dequeue_timed(true).is_none());
    let mut marker = empty.clone();
    marker.extend([0, 0x68, 0x34, 0]);
    assert_eq!(b.queue(&marker, true), 0);
    assert!(b.dequeue_timed(true).is_none());
    assert_eq!(b.queue(&packet(1, 480), true), 1);
    let real = b.dequeue_timed(true).unwrap();
    assert_eq!((real.sequence, real.timestamp), (1, 480));
}
