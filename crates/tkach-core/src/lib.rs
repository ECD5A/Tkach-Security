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

//! Provider-independent deterministic security primitives.
//!
//! This crate is intentionally small. External messages must be validated into
//! these types before reaching the kernel; provider adapters are out of scope.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The Strong Core's public security domain. Mandates add enforcement behind
/// these stable conceptual boundaries in small, auditable increments.
pub mod domain;

/// DATA/CONTROL authority containment boundary.
pub mod gnezdo;

/// Deterministic policy representation and Krosna evaluation kernel.
pub mod krosna;

/// Deterministic ingress/egress hard-deny boundary and formal matcher.
pub mod zaslon;
