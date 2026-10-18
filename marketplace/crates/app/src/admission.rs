//! Default admission module (spec §5/§7): open registration behind a
//! feature flag and a global account cap. Implements the modules-api
//! trait; the core still owns the accounts table.

use modules_api::{Admission, AdmissionCx, AdmissionPolicy, FormInput, Module, ModuleError, ModuleId};

pub struct OpenAdmission {
    pub open: bool,
}

impl Module for OpenAdmission {
    fn id(&self) -> ModuleId {
        ModuleId("open-registration")
    }
    fn version(&self) -> semver::Version {
        semver::Version::new(1, 0, 0)
    }
    fn capabilities(&self) -> &[modules_api::Capability] {
        &[]
    }
}

impl AdmissionPolicy for OpenAdmission {
    fn admit(&self, cx: &AdmissionCx, _input: &FormInput) -> Result<Admission, ModuleError> {
        if !self.open || !cx.registrations_open {
            return Ok(Admission::Rejected);
        }
        if let Some(cap) = cx.account_cap {
            if cx.account_count >= cap {
                return Ok(Admission::Rejected);
            }
        }
        let _ = &cx.username;
        Ok(Admission::Admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx(open: bool, count: u64, cap: Option<u64>) -> AdmissionCx {
        AdmissionCx {
            username: "alice".into(),
            registrations_open: open,
            account_count: count,
            account_cap: cap,
        }
    }

    #[test]
    fn flag_cap_and_open() {
        let m = OpenAdmission { open: true };
        let inp = FormInput { fields: vec![] };
        assert!(matches!(m.admit(&cx(true, 3, None), &inp), Ok(Admission::Admitted)));
        assert!(matches!(m.admit(&cx(false, 3, None), &inp), Ok(Admission::Rejected)));
        assert!(matches!(m.admit(&cx(true, 100, Some(100)), &inp), Ok(Admission::Rejected)));
        let closed = OpenAdmission { open: false };
        assert!(matches!(closed.admit(&cx(true, 0, None), &inp), Ok(Admission::Rejected)));
    }
}
