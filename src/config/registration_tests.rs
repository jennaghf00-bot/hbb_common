use super::registration::{IdentityContext, RegistrationTracker};
use std::time::{Duration, Instant};

fn identity() -> IdentityContext {
    IdentityContext {
        actual_id: "ZBX-TEST".into(),
        generation: "generation-1".into(),
        public_fingerprint: "fixture-public-fingerprint".into(),
    }
}

#[test]
fn receipt_starts_offline_without_current_registration() {
    let tracker = RegistrationTracker::default();
    assert!(
        !tracker
            .receipt(&identity(), true, Instant::now())
            .registered
    );
}

#[test]
fn receipt_acceptance_expires_without_fresh_heartbeat() {
    let now = Instant::now();
    let mut tracker = RegistrationTracker::default();
    tracker.accept(identity(), "udp", now);
    assert!(tracker.receipt(&identity(), true, now).registered);
    assert!(
        !tracker
            .receipt(&identity(), true, now + Duration::from_secs(31))
            .registered
    );
}

#[test]
fn receipt_rejects_expected_id_with_different_service_identity() {
    let now = Instant::now();
    let mut tracker = RegistrationTracker::default();
    tracker.accept(identity(), "udp", now);
    let mut actual = identity();
    actual.actual_id = "ZBX-OTHER".into();
    assert!(!tracker.receipt(&actual, true, now).registered);
    actual = identity();
    actual.public_fingerprint = "changed-key".into();
    assert!(!tracker.receipt(&actual, true, now).registered);
    actual = identity();
    actual.generation = "another-generation".into();
    assert!(!tracker.receipt(&actual, true, now).registered);
}

#[test]
fn receipt_response_latency_or_heartbeat_alone_is_not_acceptance() {
    let now = Instant::now();
    let mut tracker = RegistrationTracker::default();
    tracker.heartbeat(&identity(), now);
    assert!(!tracker.receipt(&identity(), true, now).registered);
}

#[test]
fn receipt_rejection_and_incomplete_persistence_are_never_success() {
    let now = Instant::now();
    let mut tracker = RegistrationTracker::default();
    tracker.accept(identity(), "udp", now);
    assert!(!tracker.receipt(&identity(), false, now).registered);
    tracker.reject("identity_mismatch");
    let receipt = tracker.receipt(&identity(), true, now);
    assert!(!receipt.registered);
    assert_eq!(receipt.error_code.as_deref(), Some("identity_mismatch"));
}

#[test]
fn receipt_restart_waits_for_registration_without_a_stale_hard_error() {
    let now = Instant::now();
    let mut tracker = RegistrationTracker::default();
    tracker.reject("identity_mismatch");
    tracker.reset();
    let receipt = tracker.receipt(&identity(), true, now);
    assert_eq!(receipt.phase, "configured_offline");
    assert_eq!(receipt.error_code, None);
    assert!(!receipt.registered);
}
