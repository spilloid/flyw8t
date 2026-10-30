//! Append-only audit log. The table rejects UPDATE, DELETE and TRUNCATE at the database.

use crate::auth::Principal;
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Audit {
    actor_type: &'static str,
    actor_id: Option<Uuid>,
    actor_label: String,
    channel: &'static str,
    credential: Option<String>,
    organization_id: Option<Uuid>,
    action: &'static str,
    target_type: Option<&'static str>,
    target_id: Option<Uuid>,
    outcome: &'static str,
    client_ip: Option<String>,
    detail: Value,
}

impl Audit {
    pub fn user(p: &Principal, action: &'static str) -> Self {
        Self {
            actor_type: "user",
            actor_id: Some(p.user_id),
            actor_label: p.email.clone(),
            channel: p.channel.as_str(),
            credential: Some(p.credential.clone()),
            ..Self::base(action)
        }
    }

    pub fn device(device_id: Uuid, hostname: &str, action: &'static str) -> Self {
        Self {
            actor_type: "device",
            actor_id: Some(device_id),
            actor_label: hostname.to_string(),
            channel: "agent",
            ..Self::base(action)
        }
    }

    pub fn anonymous(
        channel: &'static str,
        label: impl Into<String>,
        action: &'static str,
    ) -> Self {
        Self {
            actor_type: "anonymous",
            actor_label: label.into(),
            channel,
            ..Self::base(action)
        }
    }

    pub fn system(action: &'static str) -> Self {
        Self::base(action)
    }

    fn base(action: &'static str) -> Self {
        Self {
            actor_type: "system",
            actor_id: None,
            actor_label: "flyw8t".into(),
            channel: "system",
            credential: None,
            organization_id: None,
            action,
            target_type: None,
            target_id: None,
            outcome: "success",
            client_ip: None,
            detail: Value::Object(Default::default()),
        }
    }

    pub fn org(mut self, id: Uuid) -> Self {
        self.organization_id = Some(id);
        self
    }

    pub fn target(mut self, kind: &'static str, id: Uuid) -> Self {
        self.target_type = Some(kind);
        self.target_id = Some(id);
        self
    }

    pub fn denied(mut self) -> Self {
        self.outcome = "denied";
        self
    }

    pub fn failed(mut self) -> Self {
        self.outcome = "failed";
        self
    }

    pub fn ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    pub async fn record<'e, E: sqlx::PgExecutor<'e>>(self, exec: E) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO audit_events (actor_type, actor_id, actor_label, channel, credential, organization_id,
                                       action, target_type, target_id, outcome, client_ip, detail)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(self.actor_type)
        .bind(self.actor_id)
        .bind(self.actor_label)
        .bind(self.channel)
        .bind(self.credential)
        .bind(self.organization_id)
        .bind(self.action)
        .bind(self.target_type)
        .bind(self.target_id)
        .bind(self.outcome)
        .bind(self.client_ip)
        .bind(self.detail)
        .execute(exec)
        .await?;
        Ok(())
    }
}
