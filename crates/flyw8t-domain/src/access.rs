//! Roles and permissions.
//!
//! A role says what kinds of things a user may do. Which organizations they may do them in is
//! a separate check (the server's organization scope): `admin` spans every organization;
//! `technician` and `readonly` see only organizations they are assigned to. Both checks must
//! pass, and an API token's scopes can only narrow the result further.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Technician,
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ViewDevices,
    RunDiagnostics,
    CancelJobs,
    ManageEnrollment,
    ManageOrganizations,
    ManageUsers,
    ViewAudit,
    RunSupportSessions,
    /// Attended sessions that include remote keyboard and mouse (ADR-0012). Separate from
    /// viewing so it can be withheld on its own.
    RunControlSessions,
    /// Name, notes, tags and site of devices in the user's organizations.
    ManageDevices,
    /// Retiring a device: permanent.
    RetireDevices,
    /// Defining custom fields and setting global values.
    ManageFields,
    /// Setting organization and device values of custom fields that allow technicians to.
    EditFieldValues,
    /// Reading scripts in the script library: global ones, and those of the user's organizations.
    ViewScripts,
    /// Creating scripts and saving draft revisions, global ones included (ADR-0014). Drafts never run.
    EditScripts,
    /// Starting a run of an approved script on a device (ADR-0015). What runs is decided by the approvals and run
    /// signatures the agent checks, not by this permission.
    RunScripts,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Technician => "technician",
            Role::ReadOnly => "readonly",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            "technician" => Some(Role::Technician),
            "readonly" => Some(Role::ReadOnly),
            _ => None,
        }
    }

    /// Whether this role spans every organization without explicit assignment.
    pub fn is_global(self) -> bool {
        self == Role::Admin
    }

    pub fn allows(self, p: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Admin => true,
            Role::Technician => matches!(
                p,
                ViewDevices
                    | RunDiagnostics
                    | CancelJobs
                    | ManageEnrollment
                    | RunSupportSessions
                    | RunControlSessions
                    | ManageDevices
                    | EditFieldValues
                    | ViewScripts
                    | EditScripts
                    | RunScripts
            ),
            Role::ReadOnly => matches!(p, ViewDevices),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_cannot_act() {
        assert!(Role::ReadOnly.allows(Permission::ViewDevices));
        for p in [
            Permission::RunDiagnostics,
            Permission::CancelJobs,
            Permission::ManageEnrollment,
            Permission::ManageOrganizations,
            Permission::ManageUsers,
            Permission::ViewAudit,
            Permission::RunSupportSessions,
            Permission::RunControlSessions,
            Permission::ManageDevices,
            Permission::RetireDevices,
            Permission::ManageFields,
            Permission::EditFieldValues,
            Permission::ViewScripts,
            Permission::EditScripts,
            Permission::RunScripts,
        ] {
            assert!(!Role::ReadOnly.allows(p), "{p:?}");
        }
    }

    #[test]
    fn technicians_cannot_administer() {
        assert!(Role::Technician.allows(Permission::RunDiagnostics));
        assert!(!Role::Technician.allows(Permission::ManageUsers));
        assert!(!Role::Technician.allows(Permission::ManageOrganizations));
        assert!(Role::Technician.allows(Permission::ManageDevices));
        assert!(!Role::Technician.allows(Permission::RetireDevices));
        assert!(!Role::Technician.allows(Permission::ManageFields));
        assert!(Role::Technician.allows(Permission::EditScripts));
        assert!(!Role::Technician.is_global());
    }
}
