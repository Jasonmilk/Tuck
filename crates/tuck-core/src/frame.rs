//! CI-144 frame parser — zero-copy BIND-19 frame parsing with PFP 4-byte extraction.
//!
//! # Design Principle
//!
//! **极致节能**: Frame parsing is zero-copy — no heap allocation, no data
//! copying. The parser works with byte slices (`&[u8]`) and returns references
//! into the original buffer. PFP extraction is a simple 4-byte slice.
//!
//! **极致解耦**: The frame parser is independent of the decision engine.
//! It only parses frames — `decide()` operates on the extracted PFP bytes.
//!
//! **物理事实优先**: Frame layout is fixed-offset, defined by the CI-144
//! protocol specification. No dynamic parsing, no length-prefix ambiguity.
//!
//! # Frame Layout
//!
//! ```text
//! [ 8-byte BIND-19 Header ] [ 4-byte PFP ] [ 28-byte SAP (optional) ] [ Payload ]
//! ```
//!
//! ## BIND-19 Header (8 bytes)
//!
//! | Offset | Size | Field | Description |
//! |--------|------|-------|-------------|
//! | 0      | 2    | Magic | 0xCF14 (CI-144 family magic) |
//! | 2      | 1    | Flags | Sub-protocol ID + feature flags |
//! | 3      | 1    | Type  | Frame type (0x01=data, 0x02=control, etc.) |
//! | 4      | 2    | Seq   | Sequence counter (16-bit, anti-replay) |
//! | 6      | 1    | Present | PFP-Present(1) + SAP-Present(1) + Reserved(6) |
//! | 7      | 1    | PayloadLen | Payload length (high byte, if >255 use extended) |
//!
//! ## PFP (Physical Feature Protocol, 4 bytes)
//!
//! | Offset | Size | Field | Description |
//! |--------|------|-------|-------------|
//! | 0      | 2    | Magic | 0xCF14 (family magic, repeated) |
//! | 2      | 1    | Features | Modality(2) + RiskLevel(2) + BodyStance(2) + ProximityEdge(2) |
//! | 3      | 1    | Flags | OutputDest(1) + OverrideFlag(1) + ReplayEnable(1) + Reserved(5) |

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// CI-144 family magic number (2 bytes).
pub const CI144_MAGIC: [u8; 2] = [0xCF, 0x14];

/// BIND-19 header size (8 bytes).
pub const HEADER_SIZE: usize = 8;

/// PFP size (4 bytes).
pub const PFP_SIZE: usize = 4;

/// SAP size (28 bytes).
pub const SAP_SIZE: usize = 28;

/// Minimum frame size (header + PFP).
pub const MIN_FRAME_SIZE: usize = HEADER_SIZE + PFP_SIZE;

/// Frame type: data frame.
pub const FRAME_TYPE_DATA: u8 = 0x01;

/// Frame type: control frame.
pub const FRAME_TYPE_CONTROL: u8 = 0x02;

/// Present flag: PFP present.
pub const PRESENT_PFP: u8 = 0b1000_0000;

/// Present flag: SAP present.
pub const PRESENT_SAP: u8 = 0b0100_0000;

// ============================================================================
// Frame Header
// ============================================================================

/// BIND-19 frame header (8 bytes, parsed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    /// CI-144 family magic (should be 0xCF14).
    pub magic: [u8; 2],
    /// Sub-protocol ID + feature flags.
    pub flags: u8,
    /// Frame type (0x01=data, 0x02=control).
    pub frame_type: u8,
    /// Sequence counter (16-bit, anti-replay).
    pub seq: u16,
    /// Present flags (PFP-Present + SAP-Present).
    pub present: u8,
    /// Payload length (low byte; extended length for large payloads).
    pub payload_len: u8,
}

impl FrameHeader {
    /// Parse a frame header from a byte slice (must be at least 8 bytes).
    pub fn parse(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < HEADER_SIZE {
            return Err(FrameError::TooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let magic = [data[0], data[1]];
        if magic != CI144_MAGIC {
            return Err(FrameError::InvalidMagic { actual: magic });
        }

        Ok(Self {
            magic,
            flags: data[2],
            frame_type: data[3],
            seq: u16::from_be_bytes([data[4], data[5]]),
            present: data[6],
            payload_len: data[7],
        })
    }

    /// Check if PFP is present in this frame.
    pub fn has_pfp(&self) -> bool {
        self.present & PRESENT_PFP != 0
    }

    /// Check if SAP is present in this frame.
    pub fn has_sap(&self) -> bool {
        self.present & PRESENT_SAP != 0
    }

    /// Check if the magic is valid.
    pub fn is_valid_magic(&self) -> bool {
        self.magic == CI144_MAGIC
    }

    /// Serialize the header to bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..2].copy_from_slice(&self.magic);
        bytes[2] = self.flags;
        bytes[3] = self.frame_type;
        bytes[4..6].copy_from_slice(&self.seq.to_be_bytes());
        bytes[6] = self.present;
        bytes[7] = self.payload_len;
        bytes
    }
}

// ============================================================================
// Frame
// ============================================================================

/// A parsed CI-144 frame with references to the original buffer.
///
/// This is a zero-copy view — all fields are references into the original
/// byte slice. The frame does not own any data.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// Frame header.
    pub header: FrameHeader,
    /// PFP bytes (4 bytes, if present).
    pub pfp: Option<&'a [u8]>,
    /// SAP bytes (28 bytes, if present).
    pub sap: Option<&'a [u8]>,
    /// Payload bytes (variable length).
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parse a frame from a byte slice (zero-copy).
    ///
    /// Returns a `Frame` with references into the original buffer.
    /// The buffer must outlive the returned `Frame`.
    pub fn parse(data: &'a [u8]) -> Result<Self, FrameError> {
        if data.len() < HEADER_SIZE {
            return Err(FrameError::TooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let header = FrameHeader::parse(&data[0..HEADER_SIZE])?;

        let mut offset = HEADER_SIZE;

        // Extract PFP (4 bytes)
        let pfp = if header.has_pfp() {
            if data.len() < offset + PFP_SIZE {
                return Err(FrameError::TruncatedPfp {
                    offset,
                    available: data.len() - offset,
                });
            }
            let pfp_data = &data[offset..offset + PFP_SIZE];
            offset += PFP_SIZE;
            Some(pfp_data)
        } else {
            None
        };

        // Extract SAP (28 bytes)
        let sap = if header.has_sap() {
            if data.len() < offset + SAP_SIZE {
                return Err(FrameError::TruncatedSap {
                    offset,
                    available: data.len() - offset,
                });
            }
            let sap_data = &data[offset..offset + SAP_SIZE];
            offset += SAP_SIZE;
            Some(sap_data)
        } else {
            None
        };

        // Remaining bytes are payload
        let payload = &data[offset..];

        Ok(Self {
            header,
            pfp,
            sap,
            payload,
        })
    }

    /// Extract PFP 4 bytes (convenience method).
    ///
    /// Returns the PFP bytes if present, or an error if not present.
    pub fn extract_pfp(&self) -> Result<&[u8], FrameError> {
        self.pfp.ok_or(FrameError::PfpNotPresent)
    }

    /// Get the total frame size (header + PFP + SAP + payload).
    pub fn total_size(&self) -> usize {
        let mut size = HEADER_SIZE;
        if self.pfp.is_some() {
            size += PFP_SIZE;
        }
        if self.sap.is_some() {
            size += SAP_SIZE;
        }
        size += self.payload.len();
        size
    }

    /// Check if the frame is a data frame.
    pub fn is_data_frame(&self) -> bool {
        self.header.frame_type == FRAME_TYPE_DATA
    }

    /// Check if the frame is a control frame.
    pub fn is_control_frame(&self) -> bool {
        self.header.frame_type == FRAME_TYPE_CONTROL
    }
}

// ============================================================================
// Frame Builder (for testing)
// ============================================================================

/// Frame builder — construct frames for testing or sending.
#[derive(Debug, Clone)]
pub struct FrameBuilder {
    header: FrameHeader,
    pfp: Option<[u8; PFP_SIZE]>,
    sap: Option<[u8; SAP_SIZE]>,
    payload: Vec<u8>,
}

impl FrameBuilder {
    /// Create a new frame builder with default header.
    pub fn new() -> Self {
        Self {
            header: FrameHeader {
                magic: CI144_MAGIC,
                flags: 0,
                frame_type: FRAME_TYPE_DATA,
                seq: 0,
                present: 0,
                payload_len: 0,
            },
            pfp: None,
            sap: None,
            payload: Vec::new(),
        }
    }

    /// Set the sequence counter.
    pub fn with_seq(mut self, seq: u16) -> Self {
        self.header.seq = seq;
        self
    }

    /// Set the frame type.
    pub fn with_frame_type(mut self, frame_type: u8) -> Self {
        self.header.frame_type = frame_type;
        self
    }

    /// Add PFP bytes.
    pub fn with_pfp(mut self, pfp: [u8; PFP_SIZE]) -> Self {
        self.pfp = Some(pfp);
        self.header.present |= PRESENT_PFP;
        self
    }

    /// Add SAP bytes.
    pub fn with_sap(mut self, sap: [u8; SAP_SIZE]) -> Self {
        self.sap = Some(sap);
        self.header.present |= PRESENT_SAP;
        self
    }

    /// Set the payload.
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.header.payload_len = payload.len().min(255) as u8;
        self.payload = payload;
        self
    }

    /// Build the frame into a byte vector.
    pub fn build(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.header.to_bytes());
        if let Some(pfp) = self.pfp {
            bytes.extend_from_slice(&pfp);
        }
        if let Some(sap) = self.sap {
            bytes.extend_from_slice(&sap);
        }
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Get the total size of the frame.
    fn total_size(&self) -> usize {
        let mut size = HEADER_SIZE;
        if self.pfp.is_some() {
            size += PFP_SIZE;
        }
        if self.sap.is_some() {
            size += SAP_SIZE;
        }
        size += self.payload.len();
        size
    }
}

impl Default for FrameBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Frame parsing error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Frame is too short.
    #[error("frame too short: expected {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    /// Invalid magic number.
    #[error("invalid magic: expected 0xCF14, got 0x{:02X}{:02X}", actual[0], actual[1])]
    InvalidMagic { actual: [u8; 2] },

    /// PFP section is truncated.
    #[error("truncated PFP at offset {offset}: expected 4 bytes, got {available}")]
    TruncatedPfp { offset: usize, available: usize },

    /// SAP section is truncated.
    #[error("truncated SAP at offset {offset}: expected 28 bytes, got {available}")]
    TruncatedSap { offset: usize, available: usize },

    /// PFP is not present in this frame.
    #[error("PFP not present in frame")]
    PfpNotPresent,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse_valid() {
        let data = [
            0xCF, 0x14, // magic
            0x00, // flags
            0x01, // frame type (data)
            0x00, 0x01, // seq = 1
            PRESENT_PFP, // present: PFP only
            0x00, // payload len
        ];

        let header = FrameHeader::parse(&data).unwrap();
        assert!(header.is_valid_magic());
        assert_eq!(header.frame_type, FRAME_TYPE_DATA);
        assert_eq!(header.seq, 1);
        assert!(header.has_pfp());
        assert!(!header.has_sap());
    }

    #[test]
    fn test_header_parse_invalid_magic() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let result = FrameHeader::parse(&data);
        assert!(matches!(result, Err(FrameError::InvalidMagic { .. })));
    }

    #[test]
    fn test_header_parse_too_short() {
        let data = [0xCF, 0x14, 0x00];
        let result = FrameHeader::parse(&data);
        assert!(matches!(result, Err(FrameError::TooShort { .. })));
    }

    #[test]
    fn test_header_to_bytes_roundtrip() {
        let header = FrameHeader {
            magic: CI144_MAGIC,
            flags: 0xAB,
            frame_type: FRAME_TYPE_DATA,
            seq: 12345,
            present: PRESENT_PFP | PRESENT_SAP,
            payload_len: 42,
        };

        let bytes = header.to_bytes();
        let parsed = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn test_frame_parse_with_pfp() {
        let pfp = [0xCF, 0x14, 0b00_01_10_11, 0b1_1_1_00000];
        let frame_bytes = FrameBuilder::new()
            .with_seq(42)
            .with_pfp(pfp)
            .with_payload(vec![1, 2, 3])
            .build();

        let frame = Frame::parse(&frame_bytes).unwrap();
        assert_eq!(frame.header.seq, 42);
        assert!(frame.pfp.is_some());
        assert_eq!(frame.pfp.unwrap(), &pfp);
        assert_eq!(frame.payload, &[1, 2, 3]);
        assert_eq!(frame.total_size(), HEADER_SIZE + PFP_SIZE + 3);
    }

    #[test]
    fn test_frame_parse_with_pfp_and_sap() {
        let pfp = [0xCF, 0x14, 0x00, 0x00];
        let sap = [0u8; SAP_SIZE];
        let frame_bytes = FrameBuilder::new()
            .with_pfp(pfp)
            .with_sap(sap)
            .with_payload(vec![4, 5, 6])
            .build();

        let frame = Frame::parse(&frame_bytes).unwrap();
        assert!(frame.pfp.is_some());
        assert!(frame.sap.is_some());
        assert_eq!(frame.sap.unwrap().len(), SAP_SIZE);
        assert_eq!(frame.payload, &[4, 5, 6]);
        assert_eq!(frame.total_size(), HEADER_SIZE + PFP_SIZE + SAP_SIZE + 3);
    }

    #[test]
    fn test_frame_parse_no_pfp() {
        let frame_bytes = FrameBuilder::new()
            .with_payload(vec![7, 8, 9])
            .build();

        let frame = Frame::parse(&frame_bytes).unwrap();
        assert!(frame.pfp.is_none());
        assert!(frame.sap.is_none());
        assert_eq!(frame.payload, &[7, 8, 9]);
    }

    #[test]
    fn test_frame_extract_pfp() {
        let pfp = [0xCF, 0x14, 0b10_11_00_01, 0b0_1_0_00000];
        let frame_bytes = FrameBuilder::new()
            .with_pfp(pfp)
            .build();

        let frame = Frame::parse(&frame_bytes).unwrap();
        let extracted = frame.extract_pfp().unwrap();
        assert_eq!(extracted, &pfp);
    }

    #[test]
    fn test_frame_extract_pfp_not_present() {
        let frame_bytes = FrameBuilder::new().build();
        let frame = Frame::parse(&frame_bytes).unwrap();
        let result = frame.extract_pfp();
        assert!(matches!(result, Err(FrameError::PfpNotPresent)));
    }

    #[test]
    fn test_frame_parse_too_short() {
        let data = [0xCF, 0x14, 0x00];
        let result = Frame::parse(&data);
        assert!(matches!(result, Err(FrameError::TooShort { .. })));
    }

    #[test]
    fn test_frame_parse_truncated_pfp() {
        // Header says PFP present, but only 2 bytes after header
        let mut data = vec![0u8; HEADER_SIZE + 2];
        data[0..2].copy_from_slice(&CI144_MAGIC);
        data[6] = PRESENT_PFP;

        let result = Frame::parse(&data);
        assert!(matches!(result, Err(FrameError::TruncatedPfp { .. })));
    }

    #[test]
    fn test_frame_is_data_frame() {
        let frame_bytes = FrameBuilder::new()
            .with_frame_type(FRAME_TYPE_DATA)
            .build();
        let frame = Frame::parse(&frame_bytes).unwrap();
        assert!(frame.is_data_frame());
        assert!(!frame.is_control_frame());
    }

    #[test]
    fn test_frame_is_control_frame() {
        let frame_bytes = FrameBuilder::new()
            .with_frame_type(FRAME_TYPE_CONTROL)
            .build();
        let frame = Frame::parse(&frame_bytes).unwrap();
        assert!(frame.is_control_frame());
        assert!(!frame.is_data_frame());
    }

    #[test]
    fn test_frame_builder_default() {
        let builder = FrameBuilder::default();
        let bytes = builder.build();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let frame = Frame::parse(&bytes).unwrap();
        assert!(frame.header.is_valid_magic());
        assert_eq!(frame.header.frame_type, FRAME_TYPE_DATA);
        assert!(frame.pfp.is_none());
    }

    #[test]
    fn test_frame_zero_copy_no_allocation() {
        // Verify that parsing doesn't allocate (Frame holds references)
        let pfp = [0xCF, 0x14, 0x00, 0x00];
        let frame_bytes = FrameBuilder::new()
            .with_pfp(pfp)
            .with_payload(vec![1, 2, 3, 4, 5])
            .build();

        let frame = Frame::parse(&frame_bytes).unwrap();

        // Verify references point into original buffer (zero-copy)
        // Compare pointer addresses without unsafe
        let base_addr = frame_bytes.as_ptr() as usize;
        let pfp_addr = frame.pfp.unwrap().as_ptr() as usize;
        let payload_addr = frame.payload.as_ptr() as usize;

        assert_eq!(pfp_addr, base_addr + HEADER_SIZE);
        assert_eq!(payload_addr, base_addr + HEADER_SIZE + PFP_SIZE);
    }

    #[test]
    fn test_frame_large_payload() {
        let payload = vec![0xABu8; 1024];
        let frame_bytes = FrameBuilder::new()
            .with_pfp([0xCF, 0x14, 0x00, 0x00])
            .with_payload(payload.clone())
            .build();

        let frame = Frame::parse(&frame_bytes).unwrap();
        assert_eq!(frame.payload.len(), 1024);
        assert_eq!(frame.payload, &payload);
        assert_eq!(frame.total_size(), HEADER_SIZE + PFP_SIZE + 1024);
    }
}
