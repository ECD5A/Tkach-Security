/*
 * Tkach Security
 *
 * Copyright 2026 ECD5A
 * Licensed under the Apache License, Version 2.0.
 *
 * Repository: https://github.com/ECD5A/Tkach-Security
 *
 * See LICENSE and SECURITY.md.
 */

//! Protected effect boundaries for the provider-independent Gateway.

use std::fmt::{Debug, Formatter};
use std::fs::{self, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tkach_core::domain::{
    ActionRequest, CapabilityName, Classification, Destination, Identity, Operation,
    ProvenanceSource, Resource, ResourceId, ResourceKind,
};
use tkach_core::klyuchnik::{FakeBroker, SecretBroker, SecretHandle};
use tkach_core::niti_metka::TaggedData;
use tkach_core::propusk::{ExecutionError, Propusk, ProtectedExecutor};

const MAX_FAKE_EFFECTS: usize = 1_024;
const MAX_REAL_ATTEMPTS: u64 = 1_024;
const MAX_NETWORK_RESPONSE_BYTES: usize = 8 * 1024;
const EFFECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Fixed trusted file contents used by the create-only local write boundary.
///
/// The provider cannot replace this value with an action field or a model
/// payload. Applications needing a different payload must define a separate
/// reviewed executor binding rather than adding a general write API.
pub const REAL_FILE_WRITE_CONTENT: &[u8] = b"tkach-security-local-file-effect\n";

/// Fixed trusted path used by the local loopback HTTP effect boundary.
pub const REAL_NETWORK_PATH: &str = "/tkach-security/local-effect";

/// Fixed trusted body used by the local loopback HTTP effect boundary.
pub const REAL_NETWORK_PAYLOAD: &[u8] = b"tkach-security-local-network-effect";

/// Configuration errors for [`RealEffectExecutor`]. They intentionally carry
/// no filesystem paths, socket details, or other caller-controlled text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RealExecutorConfigError {
    /// The supplied root was not an existing ordinary directory.
    #[error("real executor sandbox root is invalid")]
    InvalidSandboxRoot,
    /// The supplied endpoint was not a non-zero loopback socket address.
    #[error("real executor endpoint must be a non-zero loopback address")]
    InvalidLoopbackEndpoint,
}

/// Outcome represented by a successful effect receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectOutcome {
    /// The executor completed its local commit/response check.
    Committed,
}

/// A payload-free summary of one authorized effect.
#[derive(Clone, PartialEq, Eq)]
pub struct EffectReceipt {
    operation: Operation,
    resource_kind: ResourceKind,
    destination: Destination,
    execution_id: u64,
    outcome: EffectOutcome,
}

impl Debug for EffectReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EffectReceipt(REDACTED)")
    }
}

impl EffectReceipt {
    /// Return the operation category of the authorized effect.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Return the resource category without an attacker-controlled identifier.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Return the typed destination used by the effect.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Return the bounded per-executor sequence number for this effect.
    #[must_use]
    pub const fn execution_id(&self) -> u64 {
        self.execution_id
    }

    /// Return the verified outcome represented by this receipt.
    #[must_use]
    pub const fn outcome(&self) -> EffectOutcome {
        self.outcome
    }
}

/// Result returned by a protected tool. Data results retain Niti and Metka;
/// effect receipts carry no protected payload.
#[derive(Clone, PartialEq, Eq)]
pub enum ToolResult {
    /// A protected or public result intentionally made visible to the model.
    Data(TaggedData<String>),
    /// A completed effect with a payload-free receipt.
    Effect(EffectReceipt),
}

impl Debug for ToolResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(value) => formatter.debug_tuple("Data").field(value).finish(),
            Self::Effect(value) => formatter.debug_tuple("Effect").field(value).finish(),
        }
    }
}

/// A real local filesystem and loopback-network effect executor.
///
/// The executor accepts only kernel-issued [`Propusk`] values. It has two
/// immutable filesystem bindings (`workspace/input.txt` for read and
/// `workspace/output.txt` for a create-only write) and one immutable HTTP
/// binding (`public-api` to the configured loopback endpoint). No action field
/// supplies an operating-system path, network address, URL, or payload.
/// Existing output files are rejected; overwrite is not part of this contract.
///
/// Filesystem checks use canonicalized paths and reject links/reparse points at
/// the root, parent, and target checks. Standard safe Rust does not provide a
/// portable handle-relative open/no-follow primitive, so a concurrent attacker
/// can still race a path lookup after validation on platforms where the OS
/// lacks an exposed safe primitive. Such races are reported as unknown only
/// after an effect may have begun; they are not claimed to be impossible.
pub struct RealEffectExecutor {
    sandbox_root: PathBuf,
    endpoint: SocketAddr,
    attempts: u64,
    committed_effects: u64,
    unknown_effects: u64,
    successful_reads: u64,
}

impl Debug for RealEffectExecutor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealEffectExecutor")
            .field("attempts", &self.attempts)
            .field("committed_effects", &self.committed_effects)
            .field("unknown_effects", &self.unknown_effects)
            .field("successful_reads", &self.successful_reads)
            .finish_non_exhaustive()
    }
}

impl RealEffectExecutor {
    /// Construct a real executor rooted at an existing ordinary directory.
    ///
    /// The root itself must not be a symlink or reparse point. The endpoint
    /// must be an explicit non-zero loopback address; DNS, Internet addresses,
    /// and port zero are rejected.
    ///
    /// # Errors
    ///
    /// Returns a payload-free configuration error when either boundary is not
    /// safe to bind.
    pub fn new(
        sandbox_root: impl AsRef<Path>,
        endpoint: SocketAddr,
    ) -> Result<Self, RealExecutorConfigError> {
        let supplied_root = sandbox_root.as_ref();
        let supplied_metadata = fs::symlink_metadata(supplied_root)
            .map_err(|_| RealExecutorConfigError::InvalidSandboxRoot)?;
        if !supplied_metadata.is_dir() || is_link_or_reparse(&supplied_metadata) {
            return Err(RealExecutorConfigError::InvalidSandboxRoot);
        }
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(RealExecutorConfigError::InvalidLoopbackEndpoint);
        }
        let canonical_root = fs::canonicalize(supplied_root)
            .map_err(|_| RealExecutorConfigError::InvalidSandboxRoot)?;
        let canonical_metadata = fs::symlink_metadata(&canonical_root)
            .map_err(|_| RealExecutorConfigError::InvalidSandboxRoot)?;
        if !canonical_metadata.is_dir() || is_link_or_reparse(&canonical_metadata) {
            return Err(RealExecutorConfigError::InvalidSandboxRoot);
        }
        Ok(Self {
            sandbox_root: canonical_root,
            endpoint,
            attempts: 0,
            committed_effects: 0,
            unknown_effects: 0,
            successful_reads: 0,
        })
    }

    /// Return the number of bounded executor attempts, including failures.
    #[must_use]
    pub const fn attempt_count(&self) -> u64 {
        self.attempts
    }

    /// Return the number of filesystem/network effects with verified success.
    #[must_use]
    pub const fn committed_effect_count(&self) -> u64 {
        self.committed_effects
    }

    /// Return the number of attempts whose final real-world outcome is unknown.
    #[must_use]
    pub const fn unknown_effect_count(&self) -> u64 {
        self.unknown_effects
    }

    /// Return the number of successful exact filesystem reads.
    #[must_use]
    pub const fn successful_read_count(&self) -> u64 {
        self.successful_reads
    }

    fn begin_attempt(&mut self) -> Result<u64, ExecutionError> {
        if self.attempts >= MAX_REAL_ATTEMPTS {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        self.attempts += 1;
        Ok(self.attempts)
    }

    fn mark_unknown<T>(&mut self) -> Result<T, ExecutionError> {
        self.unknown_effects = self.unknown_effects.saturating_add(1);
        Err(ExecutionError::OutcomeUnknown)
    }

    fn committed_receipt(
        &mut self,
        action: &Propusk,
        execution_id: u64,
    ) -> Result<EffectReceipt, ExecutionError> {
        if self.committed_effects >= MAX_REAL_ATTEMPTS {
            return self.mark_unknown();
        }
        self.committed_effects += 1;
        Ok(EffectReceipt {
            operation: action.request().operation().clone(),
            resource_kind: action.request().resource().kind(),
            destination: action.request().destination().clone(),
            execution_id,
            outcome: EffectOutcome::Committed,
        })
    }

    fn execute_read(&mut self, action: &Propusk) -> Result<ToolResult, ExecutionError> {
        let path = self.checked_existing_path("workspace/input.txt")?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|_| ExecutionError::FailedBeforeEffect)?;
        if self.checked_existing_path("workspace/input.txt").is_err() {
            return Err(ExecutionError::OutcomeUnknown);
        }
        let mut bytes = Vec::with_capacity(crate::MAX_TOOL_RESULT_BYTES + 1);
        std::io::Read::by_ref(&mut file)
            .take((crate::MAX_TOOL_RESULT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ExecutionError::FailedBeforeEffect)?;
        if bytes.len() > crate::MAX_TOOL_RESULT_BYTES {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        let value = String::from_utf8(bytes).map_err(|_| ExecutionError::FailedBeforeEffect)?;
        let source = ProvenanceSource::File(
            ResourceId::new("workspace/input.txt")
                .map_err(|_| ExecutionError::FailedBeforeEffect)?,
        );
        let tagged = TaggedData::from_trusted_ingress(value, source, Classification::Confidential)
            .map_err(|_| ExecutionError::FailedBeforeEffect)?;
        self.successful_reads += 1;
        let _ = action;
        Ok(ToolResult::Data(tagged))
    }

    fn execute_write(
        &mut self,
        action: &Propusk,
        execution_id: u64,
    ) -> Result<ToolResult, ExecutionError> {
        let path = self.checked_new_path("workspace/output.txt")?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| ExecutionError::FailedBeforeEffect)?;

        if file.write_all(REAL_FILE_WRITE_CONTENT).is_err()
            || file.flush().is_err()
            || file.sync_all().is_err()
        {
            return self.mark_unknown();
        }
        if file.seek(SeekFrom::Start(0)).is_err() {
            return self.mark_unknown();
        }
        let mut verified = vec![0_u8; REAL_FILE_WRITE_CONTENT.len()];
        if file.read_exact(&mut verified).is_err() || verified != REAL_FILE_WRITE_CONTENT {
            return self.mark_unknown();
        }
        let mut extra = [0_u8; 1];
        match file.read(&mut extra) {
            Ok(0) => {}
            Ok(_) | Err(_) => return self.mark_unknown(),
        }
        if self.checked_existing_path("workspace/output.txt").is_err() {
            return self.mark_unknown();
        }
        drop(file);
        Ok(ToolResult::Effect(
            self.committed_receipt(action, execution_id)?,
        ))
    }

    fn execute_network(
        &mut self,
        action: &Propusk,
        execution_id: u64,
    ) -> Result<ToolResult, ExecutionError> {
        let mut stream = TcpStream::connect_timeout(&self.endpoint, EFFECT_TIMEOUT)
            .map_err(|_| ExecutionError::FailedBeforeEffect)?;
        if stream.set_write_timeout(Some(EFFECT_TIMEOUT)).is_err()
            || stream.set_read_timeout(Some(EFFECT_TIMEOUT)).is_err()
        {
            return self.mark_unknown();
        }
        let host = self.endpoint.to_string();
        let request = format!(
            "POST {REAL_NETWORK_PATH} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            REAL_NETWORK_PAYLOAD.len()
        );
        if stream.write_all(request.as_bytes()).is_err()
            || stream.write_all(REAL_NETWORK_PAYLOAD).is_err()
            || stream.flush().is_err()
            || stream.shutdown(Shutdown::Write).is_err()
        {
            return self.mark_unknown();
        }
        let mut response = Vec::with_capacity(MAX_NETWORK_RESPONSE_BYTES);
        loop {
            let mut chunk = [0_u8; 512];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    if response.len().saturating_add(count) > MAX_NETWORK_RESPONSE_BYTES {
                        return self.mark_unknown();
                    }
                    response.extend_from_slice(&chunk[..count]);
                }
                Err(_) => return self.mark_unknown(),
            }
        }
        if !is_successful_http_response(&response) {
            return self.mark_unknown();
        }
        Ok(ToolResult::Effect(
            self.committed_receipt(action, execution_id)?,
        ))
    }

    fn checked_parent(&self, relative: &str) -> Result<PathBuf, ExecutionError> {
        let relative_path = Path::new(relative);
        if !is_safe_relative_path(relative_path) {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        let path = self.sandbox_root.join(relative_path);
        let parent = path.parent().ok_or(ExecutionError::FailedBeforeEffect)?;
        let metadata =
            fs::symlink_metadata(parent).map_err(|_| ExecutionError::FailedBeforeEffect)?;
        if !metadata.is_dir() || is_link_or_reparse(&metadata) {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        let canonical_parent =
            fs::canonicalize(parent).map_err(|_| ExecutionError::FailedBeforeEffect)?;
        if !canonical_parent.starts_with(&self.sandbox_root) {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        Ok(path)
    }

    fn checked_existing_path(&self, relative: &str) -> Result<PathBuf, ExecutionError> {
        let path = self.checked_parent(relative)?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| ExecutionError::FailedBeforeEffect)?;
        if !metadata.is_file() || is_link_or_reparse(&metadata) {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        let canonical = fs::canonicalize(&path).map_err(|_| ExecutionError::FailedBeforeEffect)?;
        if !canonical.starts_with(&self.sandbox_root) {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        Ok(path)
    }

    fn checked_new_path(&self, relative: &str) -> Result<PathBuf, ExecutionError> {
        let path = self.checked_parent(relative)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
            Ok(_) | Err(_) => Err(ExecutionError::FailedBeforeEffect),
        }
    }
}

impl ProtectedExecutor for RealEffectExecutor {
    type Output = ToolResult;

    fn execute(&mut self, action: Propusk) -> Result<Self::Output, ExecutionError> {
        let execution_id = self.begin_attempt()?;
        let request = action.request();
        if request.principal() != &tkach_core::domain::Principal::Model {
            return Err(ExecutionError::FailedBeforeEffect);
        }
        if request.operation() == &Operation::Read
            && request.capability().as_str() == "file.read"
            && request.resource().kind() == ResourceKind::File
            && request.resource().id().as_str() == "workspace/input.txt"
            && request.destination() == &Destination::Model
        {
            return self.execute_read(&action);
        }
        if request.operation() == &Operation::Write
            && request.capability().as_str() == "file.write"
            && request.resource().kind() == ResourceKind::File
            && request.resource().id().as_str() == "workspace/output.txt"
            && is_storage_destination(request.destination())
        {
            return self.execute_write(&action, execution_id);
        }
        if request.operation() == &Operation::NetworkSend
            && request.capability().as_str() == "network.send"
            && request.resource().kind() == ResourceKind::Network
            && request.resource().id().as_str() == "public-api"
            && request.destination() == &Destination::PublicExternal
        {
            return self.execute_network(&action, execution_id);
        }
        Err(ExecutionError::FailedBeforeEffect)
    }
}

fn is_safe_relative_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    if path.is_absolute()
        || raw.is_empty()
        || raw.contains('\\')
        || raw
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return false;
    }
    path.components().all(|component| {
        matches!(
            component,
            std::path::Component::Normal(value)
                if !value.to_string_lossy().contains(':')
        )
    })
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink() || is_windows_reparse_point(metadata)
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
const fn is_windows_reparse_point(_metadata: &Metadata) -> bool {
    false
}

fn is_successful_http_response(response: &[u8]) -> bool {
    let Some(line_end) = response.windows(2).position(|window| window == b"\r\n") else {
        return false;
    };
    let Ok(line) = std::str::from_utf8(&response[..line_end]) else {
        return false;
    };
    let mut parts = line.split_ascii_whitespace();
    let version = parts.next();
    let status = parts.next().and_then(|value| value.parse::<u16>().ok());
    matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
        && status.is_some_and(|code| (200..300).contains(&code))
}

/// In-memory tool boundary used only for provider-independent gateway tests.
///
/// The provider never receives this value or a reference to it. Its executor
/// implementation accepts only Strong Core `Propusk` values.
pub struct FakeToolBroker {
    broker: FakeBroker,
    secret_handle: SecretHandle,
    effects: Vec<EffectReceipt>,
    read_count: usize,
    external_send_count: usize,
}

impl Debug for FakeToolBroker {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeToolBroker")
            .field("effect_count", &self.effects.len())
            .field("read_count", &self.read_count)
            .field("external_send_count", &self.external_send_count)
            .finish_non_exhaustive()
    }
}

impl FakeToolBroker {
    /// Construct a fake broker with one opaque handle and one fake raw secret.
    ///
    /// # Panics
    ///
    /// Only fixed, source-controlled setup values are used; a panic indicates
    /// an invariant-preserving test fixture was changed incorrectly, not an
    /// attacker-controlled input.
    #[must_use]
    pub fn new() -> Self {
        let secret_handle = SecretHandle::new("github-prod").expect("static test handle is valid");
        let mut broker = FakeBroker::new();
        broker
            .register(
                secret_handle.clone(),
                b"fake-github-production-secret".to_vec(),
            )
            .expect("static fake broker setup is within bounds");
        Self {
            broker,
            secret_handle,
            effects: Vec::new(),
            read_count: 0,
            external_send_count: 0,
        }
    }

    /// Return the opaque handle advertised to a model-facing tool catalog.
    #[must_use]
    pub const fn secret_handle(&self) -> &SecretHandle {
        &self.secret_handle
    }

    /// Return the number of effects accepted by the protected executor.
    #[must_use]
    pub fn effect_count(&self) -> usize {
        self.effects.len()
    }

    /// Return the number of protected read results produced.
    #[must_use]
    pub const fn read_count(&self) -> usize {
        self.read_count
    }

    /// Return the number of external sends that actually reached the tool.
    #[must_use]
    pub const fn external_send_count(&self) -> usize {
        self.external_send_count
    }

    /// Return safe effect receipts for inspection.
    #[must_use]
    pub fn effects(&self) -> &[EffectReceipt] {
        &self.effects
    }

    fn receipt(action: &Propusk, execution_id: u64) -> EffectReceipt {
        EffectReceipt {
            operation: action.request().operation().clone(),
            resource_kind: action.request().resource().kind(),
            destination: action.request().destination().clone(),
            execution_id,
            outcome: EffectOutcome::Committed,
        }
    }

    fn record_effect(&mut self, receipt: EffectReceipt) -> Result<(), ExecutionError> {
        if self.effects.len() >= MAX_FAKE_EFFECTS {
            return Err(ExecutionError::Rejected);
        }
        self.effects.push(receipt);
        Ok(())
    }

    fn protected_read(&mut self, action: &Propusk) -> Result<ToolResult, ExecutionError> {
        let request = action.request();
        if request.operation() != &Operation::Read
            || request.capability().as_str() != "database.read"
            || request.resource().kind() != ResourceKind::Database
            || request.resource().id().as_str() != "customer-db"
            || request.destination() != &Destination::Model
        {
            return Err(ExecutionError::Rejected);
        }
        if self.effects.len() >= MAX_FAKE_EFFECTS {
            return Err(ExecutionError::Rejected);
        }
        self.read_count += 1;
        let tagged = TaggedData::from_trusted_ingress(
            "customer=alice; balance=protected".to_owned(),
            ProvenanceSource::Database(
                ResourceId::new("customer-db").map_err(|_| ExecutionError::Rejected)?,
            ),
            tkach_core::domain::Classification::Secret,
        )
        .map_err(|_| ExecutionError::Rejected)?;
        Ok(ToolResult::Data(tagged))
    }

    fn harmless_read(&mut self, action: &Propusk) -> Result<ToolResult, ExecutionError> {
        let request = action.request();
        if request.operation() != &Operation::Read
            || request.capability().as_str() != "database.read"
            || request.resource().kind() != ResourceKind::Database
            || request.resource().id().as_str() != "status"
            || request.destination() != &Destination::Model
        {
            return Err(ExecutionError::Rejected);
        }
        if self.effects.len() >= MAX_FAKE_EFFECTS {
            return Err(ExecutionError::Rejected);
        }
        self.read_count += 1;
        let tagged = TaggedData::from_trusted_ingress(
            "status=ok".to_owned(),
            ProvenanceSource::Tool(
                Identity::new("status-tool").map_err(|_| ExecutionError::Rejected)?,
            ),
            tkach_core::domain::Classification::Public,
        )
        .map_err(|_| ExecutionError::Rejected)?;
        Ok(ToolResult::Data(tagged))
    }
}

impl Default for FakeToolBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectedExecutor for FakeToolBroker {
    type Output = ToolResult;

    fn execute(&mut self, action: Propusk) -> Result<Self::Output, ExecutionError> {
        let request = action.request();
        if request.operation() == &Operation::Read
            && request.capability().as_str() == "database.read"
            && request.resource().id().as_str() == "customer-db"
        {
            let result = self.protected_read(&action)?;
            self.record_effect(Self::receipt(&action, self.effects.len() as u64 + 1))?;
            return Ok(result);
        }
        if request.operation() == &Operation::Read
            && request.capability().as_str() == "database.read"
        {
            let result = self.harmless_read(&action)?;
            self.record_effect(Self::receipt(&action, self.effects.len() as u64 + 1))?;
            return Ok(result);
        }
        if request.operation() == &Operation::Write
            && request.capability().as_str() == "file.write"
            && request.resource().kind() == ResourceKind::File
            && is_storage_destination(request.destination())
        {
            let receipt = Self::receipt(&action, self.effects.len() as u64 + 1);
            self.record_effect(receipt.clone())?;
            return Ok(ToolResult::Effect(receipt));
        }
        if request.operation() == &Operation::NetworkSend
            && request.capability().as_str() == "network.send"
            && request.resource().kind() == ResourceKind::Network
            && request.destination() == &Destination::PublicExternal
        {
            if self.effects.len() >= MAX_FAKE_EFFECTS {
                return Err(ExecutionError::Rejected);
            }
            self.external_send_count += 1;
            let receipt = Self::receipt(&action, self.effects.len() as u64 + 1);
            self.record_effect(receipt.clone())?;
            return Ok(ToolResult::Effect(receipt));
        }
        if request.operation() == &Operation::Execute
            && request.capability().as_str() == "secret.use"
            && request.resource().kind() == ResourceKind::Secret
            && request.destination() == &Destination::SecretBroker
        {
            if self.effects.len() >= MAX_FAKE_EFFECTS {
                return Err(ExecutionError::Rejected);
            }
            self.broker
                .use_authorized(&self.secret_handle, action)
                .map_err(|_| ExecutionError::Rejected)?;
            let receipt = EffectReceipt {
                operation: Operation::Execute,
                resource_kind: ResourceKind::Secret,
                destination: Destination::SecretBroker,
                execution_id: self.effects.len() as u64 + 1,
                outcome: EffectOutcome::Committed,
            };
            self.record_effect(receipt.clone())?;
            return Ok(ToolResult::Effect(receipt));
        }
        Err(ExecutionError::Rejected)
    }
}

fn is_storage_destination(destination: &Destination) -> bool {
    matches!(destination, Destination::Internal(identity) if identity.as_str() == "storage")
}

/// Build a protected database-read proposal.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn protected_read_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Read,
        Resource::new(
            ResourceKind::Database,
            ResourceId::new("customer-db").expect("static resource id is valid"),
        ),
        Destination::Model,
        CapabilityName::new("database.read").expect("static capability is valid"),
    )
}

/// Build a public external-send proposal.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn external_send_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::NetworkSend,
        Resource::new(
            ResourceKind::Network,
            ResourceId::new("public-api").expect("static resource id is valid"),
        ),
        Destination::PublicExternal,
        CapabilityName::new("network.send").expect("static capability is valid"),
    )
}

/// Build a secret-reveal proposal for hostile-provider tests.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn secret_reveal_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::RevealSecret,
        Resource::new(
            ResourceKind::Secret,
            ResourceId::new("github-prod").expect("static resource id is valid"),
        ),
        Destination::SecretBroker,
        CapabilityName::new("secret.reveal").expect("static capability is valid"),
    )
}

/// Build the fixed Klyuchnik-backed secret-use proposal.
///
/// The opaque handle identifies a broker operation; it never contains the
/// broker-held secret value and is still only an untrusted `ActionRequest` until
/// Krosna authorizes it.
///
/// # Panics
///
/// Panics only if the source-controlled fixed broker handle becomes invalid.
#[must_use]
pub fn secret_use_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Execute,
        SecretHandle::new("github-prod")
            .expect("static secret handle is valid")
            .resource(),
        Destination::SecretBroker,
        CapabilityName::new("secret.use").expect("static capability is valid"),
    )
}

/// Build a protected write proposal for lifecycle tests.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn protected_write_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Write,
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/output.txt").expect("static resource id is valid"),
        ),
        Destination::Internal(Identity::new("storage").expect("static identity is valid")),
        CapabilityName::new("file.write").expect("static capability is valid"),
    )
}

/// Build a harmless read-only tool proposal.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn harmless_read_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Read,
        Resource::new(
            ResourceKind::Database,
            ResourceId::new("status").expect("static resource id is valid"),
        ),
        Destination::Model,
        CapabilityName::new("database.read").expect("static capability is valid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tkach_core::domain::ResourceScope;
    use tkach_core::domain::{Classification, PolicyId, Principal, RuleId, SecurityContext};
    use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};

    fn permit(action: &ActionRequest) -> Propusk {
        let policy = Policy::new(
            PolicyId::new("tool-boundary-test").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-exact-test-action").unwrap(),
                RuleMatcher::any()
                    .principal(Principal::Model)
                    .operation(action.operation().clone())
                    .capability(action.capability().clone())
                    .resource(ResourceScope::exact(action.resource()))
                    .destination(action.destination().clone())
                    .classification(Classification::Unknown),
            )],
        )
        .unwrap();
        Krosna::new(policy)
            .authorize(&SecurityContext::untrusted_data(), action)
            .unwrap()
    }

    #[test]
    fn read_helpers_reject_wrong_identifier_and_destination() {
        let mut broker = FakeToolBroker::new();

        let mut wrong_customer_destination = protected_read_request();
        wrong_customer_destination = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            wrong_customer_destination.resource().clone(),
            Destination::Internal(Identity::new("storage").unwrap()),
            wrong_customer_destination.capability().clone(),
        );
        assert!(
            broker
                .protected_read(&permit(&wrong_customer_destination))
                .is_err()
        );

        let wrong_customer_id = harmless_read_request();
        assert!(broker.protected_read(&permit(&wrong_customer_id)).is_err());

        let mut wrong_status_destination = harmless_read_request();
        wrong_status_destination = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            wrong_status_destination.resource().clone(),
            Destination::Internal(Identity::new("storage").unwrap()),
            wrong_status_destination.capability().clone(),
        );
        assert!(
            broker
                .harmless_read(&permit(&wrong_status_destination))
                .is_err()
        );

        let wrong_status_id = protected_read_request();
        assert!(broker.harmless_read(&permit(&wrong_status_id)).is_err());
    }

    #[test]
    fn executor_routes_only_the_exact_write_destination() {
        let mut broker = FakeToolBroker::new();
        let wrong_destination = ActionRequest::new(
            Principal::Model,
            Operation::Write,
            protected_write_request().resource().clone(),
            Destination::Internal(Identity::new("other").unwrap()),
            protected_write_request().capability().clone(),
        );
        assert!(broker.execute(permit(&wrong_destination)).is_err());
        assert_eq!(broker.effect_count(), 0);

        let result = broker.execute(permit(&protected_write_request())).unwrap();
        assert!(matches!(result, ToolResult::Effect(_)));
        assert_eq!(broker.effect_count(), 1);
    }

    #[test]
    fn executor_rejects_network_send_to_a_non_public_destination() {
        let mut broker = FakeToolBroker::new();
        let wrong_destination = ActionRequest::new(
            Principal::Model,
            Operation::NetworkSend,
            Resource::new(
                ResourceKind::Network,
                ResourceId::new("public-api").unwrap(),
            ),
            Destination::Internal(Identity::new("storage").unwrap()),
            CapabilityName::new("network.send").unwrap(),
        );
        assert!(broker.execute(permit(&wrong_destination)).is_err());
        assert_eq!(broker.external_send_count(), 0);
    }

    #[test]
    fn kernel_cannot_mint_permits_for_coupled_unknown_read_shapes() {
        for action in [
            ActionRequest::new(
                Principal::Model,
                Operation::Write,
                protected_read_request().resource().clone(),
                Destination::Model,
                CapabilityName::new("database.read").unwrap(),
            ),
            ActionRequest::new(
                Principal::Model,
                Operation::Read,
                Resource::new(ResourceKind::File, ResourceId::new("customer-db").unwrap()),
                Destination::Model,
                CapabilityName::new("database.read").unwrap(),
            ),
        ] {
            let policy = Policy::new(
                PolicyId::new("coupled-shape-test").unwrap(),
                vec![PolicyRule::allow(
                    RuleId::new("allow-coupled-shape").unwrap(),
                    RuleMatcher::any()
                        .principal(Principal::Model)
                        .operation(action.operation().clone())
                        .capability(action.capability().clone())
                        .resource(ResourceScope::exact(action.resource()))
                        .destination(action.destination().clone())
                        .classification(Classification::Unknown),
                )],
            )
            .unwrap();
            assert!(
                Krosna::new(policy)
                    .authorize(&SecurityContext::untrusted_data(), &action)
                    .is_err()
            );
        }
    }

    #[test]
    fn real_path_parser_rejects_escape_and_normalization_syntax() {
        for value in [
            "../output.txt",
            "workspace/../output.txt",
            "/output.txt",
            "C:/output.txt",
            "workspace\\output.txt",
            "workspace/./output.txt",
        ] {
            assert!(!is_safe_relative_path(Path::new(value)), "{value}");
        }
        assert!(is_safe_relative_path(Path::new("workspace/output.txt")));
    }

    #[test]
    fn real_http_response_gate_accepts_only_bounded_success_statuses() {
        assert!(is_successful_http_response(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        ));
        assert!(is_successful_http_response(
            b"HTTP/1.0 299 Test\r\nContent-Length: 0\r\n\r\n"
        ));
        for response in [
            b"HTTP/1.1 500 Error\r\n\r\n".as_slice(),
            b"HTTP/2 200 OK\r\n\r\n".as_slice(),
            b"not-http".as_slice(),
            b"HTTP/1.1 nope\r\n\r\n".as_slice(),
        ] {
            assert!(!is_successful_http_response(response));
        }
    }
}
