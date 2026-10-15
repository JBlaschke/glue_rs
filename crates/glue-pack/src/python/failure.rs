use glue_format::{Diagnostic, DiagnosticCode};
#[derive(Debug)]
pub(crate) struct Failure(pub Diagnostic);
impl Failure {
    pub(crate) fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self(Diagnostic::new(
            code,
            message,
            "check the named Python input, runtime capability and build options",
        ))
    }
}
impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::new(DiagnosticCode::InvalidConfiguration, message)
    }
}
impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl From<Diagnostic> for Failure {
    fn from(value: Diagnostic) -> Self {
        Self(value)
    }
}
