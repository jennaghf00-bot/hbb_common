use serde_derive::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityContext {
    pub actual_id: String,
    pub generation: String,
    pub public_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceReceipt {
    pub version: u32,
    pub actual_id: String,
    pub generation: String,
    pub persisted: bool,
    pub public_fingerprint: String,
    pub registered: bool,
    pub phase: String,
    pub transport: String,
    pub error_code: Option<String>,
}

#[derive(Default)]
pub struct RegistrationTracker {
    accepted: Option<(IdentityContext, Instant)>,
    transport: String,
    error: Option<String>,
}

impl RegistrationTracker {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn accept(&mut self, identity: IdentityContext, transport: &str, now: Instant) {
        self.accepted = Some((identity, now));
        self.transport = transport.into();
        self.error = None;
    }

    pub fn heartbeat(&mut self, identity: &IdentityContext, now: Instant) {
        if let Some((accepted, last)) = &mut self.accepted {
            if accepted == identity {
                *last = now;
            }
        }
    }

    pub fn reject(&mut self, error: &str) {
        self.accepted = None;
        self.error = Some(error.into());
    }

    pub fn receipt(
        &self,
        identity: &IdentityContext,
        persisted: bool,
        now: Instant,
    ) -> ServiceReceipt {
        let registered = persisted
            && self
                .accepted
                .as_ref()
                .map(|(accepted, last)| {
                    accepted == identity
                        && now
                            .checked_duration_since(*last)
                            .map(|age| age < Duration::from_secs(30))
                            .unwrap_or(false)
                })
                .unwrap_or(false);
        ServiceReceipt {
            version: 1,
            actual_id: identity.actual_id.clone(),
            generation: identity.generation.clone(),
            persisted,
            public_fingerprint: identity.public_fingerprint.clone(),
            registered,
            phase: if registered {
                "registered"
            } else if persisted {
                "configured_offline"
            } else {
                "configuration_incomplete"
            }
            .into(),
            transport: self.transport.clone(),
            error_code: self.error.clone(),
        }
    }
}
