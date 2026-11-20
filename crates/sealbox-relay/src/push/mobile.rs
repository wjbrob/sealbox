//! FCM / APNs payload shapes — the **next** transports. No sender is implemented here: both
//! need credentials the repo does not have (an FCM service account, an APNs auth key + team
//! id + bundle id) and a device token per installation. See `docs/PUSH_RELAY.md` and the
//! "Credentials" section of `docs/PUSH_RELAY.md`.
//!
//! What these payloads say is exactly [`PushEvent`]: the app wakes, syncs over IMAP itself and
//! renders its own notification. Google and Apple therefore learn that *some* mailbox behind
//! this device got mail at this moment — and nothing else.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

use super::PushEvent;

/// FCM HTTP v1 request body (`POST https://fcm.googleapis.com/v1/projects/{project}/messages:send`),
/// data-only so the client decides what to show. `android.priority = "high"` lets a dozing
/// device wake; the embedded `apns` block makes the same message a background push on iOS
/// when FCM is used as the APNs front door.
#[derive(Clone, Debug, Serialize)]
pub struct FcmMessage {
    pub message: FcmBody,
}

#[derive(Clone, Debug, Serialize)]
pub struct FcmBody {
    pub token: String,
    pub data: FcmData,
    pub android: Value,
    pub apns: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct FcmData {
    pub registration_id: String,
    pub event: String,
    pub folder: String,
    pub sent_at: String,
}

/// APNs HTTP/2 request pieces for `POST /3/device/{device_token}`: the headers and the JSON
/// payload. Authentication (a `bearer` JWT signed with the APNs auth key) is added by the
/// future sender.
#[derive(Clone, Debug, Serialize)]
pub struct ApnsPush {
    pub device_token: String,
    pub headers: BTreeMap<&'static str, String>,
    pub payload: Value,
}

/// Build the FCM message for `event` addressed to `device_token`.
pub fn fcm_message(device_token: &str, event: &PushEvent) -> FcmMessage {
    FcmMessage {
        message: FcmBody {
            token: device_token.to_owned(),
            data: FcmData {
                registration_id: event.registration_id.clone(),
                event: wire_event(event),
                folder: event.folder.clone(),
                sent_at: event.sent_at.clone(),
            },
            android: json!({ "priority": "high" }),
            apns: json!({
                "headers": { "apns-push-type": "background", "apns-priority": "5" },
                "payload": { "aps": { "content-available": 1 } }
            }),
        },
    }
}

/// Build the APNs background push for `event`. `bundle_id` becomes `apns-topic`.
pub fn apns_push(device_token: &str, bundle_id: &str, event: &PushEvent) -> ApnsPush {
    let mut headers = BTreeMap::new();
    headers.insert("apns-push-type", "background".to_owned());
    headers.insert("apns-priority", "5".to_owned());
    headers.insert("apns-topic", bundle_id.to_owned());
    ApnsPush {
        device_token: device_token.to_owned(),
        headers,
        payload: json!({
            "aps": { "content-available": 1 },
            "registration_id": event.registration_id,
            "event": wire_event(event),
            "folder": event.folder,
            "sent_at": event.sent_at,
        }),
    }
}

fn wire_event(event: &PushEvent) -> String {
    serde_json::to_value(event.event)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "new_mail".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_leaves(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| string_leaves(x, out)),
            Value::Object(o) => o.values().for_each(|x| string_leaves(x, out)),
            _ => {}
        }
    }

    #[test]
    fn mobile_payloads_carry_only_the_event_fields() {
        let ev = PushEvent {
            registration_id: "reg-7".into(),
            event: super::super::EventKind::NewMail,
            folder: "INBOX".into(),
            sent_at: "2026-10-28T20:00:00.000Z".into(),
        };
        let fcm = serde_json::to_value(fcm_message("device-token-1", &ev)).expect("json");
        assert_eq!(fcm["message"]["token"], "device-token-1");
        assert_eq!(fcm["message"]["data"]["event"], "new_mail");
        assert_eq!(fcm["message"]["data"]["registration_id"], "reg-7");
        let mut leaves = Vec::new();
        string_leaves(&fcm["message"]["data"], &mut leaves);
        leaves.sort();
        assert_eq!(
            leaves,
            ["2026-10-28T20:00:00.000Z", "INBOX", "new_mail", "reg-7"]
        );

        let apns = apns_push("device-token-2", "dev.sealbox.app", &ev);
        assert_eq!(apns.headers["apns-topic"], "dev.sealbox.app");
        assert_eq!(apns.headers["apns-push-type"], "background");
        assert_eq!(apns.payload["aps"]["content-available"], 1);
        let mut leaves = Vec::new();
        string_leaves(&apns.payload, &mut leaves);
        leaves.sort();
        assert_eq!(
            leaves,
            ["2026-10-28T20:00:00.000Z", "INBOX", "new_mail", "reg-7"]
        );
    }
}
