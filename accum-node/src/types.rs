use serde::{Deserialize, Serialize};
use core::cmp::Ordering;

pub type Hash32 = [u8; 32];
pub type MinerId = [u8; 20];
pub type Amount = u64;
pub type Height = u64;
pub type EpochIndex = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target(pub Hash32);

impl Target {
    /// Check if hash meets target (hash < target)
    pub fn is_met_by(&self, hash: &Hash32) -> bool {
        for i in 0..32 {
            match hash[i].cmp(&self.0[i]) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
        true // equal is also valid per spec
    }

    /// Shift target left by bits (for target_share = target_block << 8)
    /// ACCUM specification: target_share = target_block << 8
    pub fn shift_left(&self, bits: usize) -> Self {
        let mut result = [0u8; 32];
        let bytes_to_shift = bits / 8;
        let bit_shift = bits % 8;

        for i in 0..32 {
            if i + bytes_to_shift < 32 {
                let mut val = self.0[i] as u16;
                
                if bit_shift > 0 {
                    val = (val << bit_shift) & 0xFF;
                    if i + bytes_to_shift + 1 < 32 {
                        result[i + bytes_to_shift + 1] |= (self.0[i] >> (8 - bit_shift)) as u8;
                    }
                }
                
                result[i + bytes_to_shift] |= val as u8;
            }
        }

        Target(result)
    }

    /// Scale target by factor (for difficulty adjustment)
    /// ACCUM specification: ±25% max change, every 120 blocks
    pub fn scaled(&self, factor: f64) -> Self {
        if factor <= 0.0 {
            return Target([0u8; 32]);
        }
        if factor == 1.0 {
            return *self;
        }

        // Proper scaling for 256-bit target
        let mut result = [0u8; 32];
        let mut carry = 0u16;

        // Scale from least significant byte to most significant
        for i in (0..32).rev() {
            let val = (self.0[i] as u16) * (factor * 256.0) as u16 + carry;
            result[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }

        // If scaling made target too large, clamp to max
        if carry > 0 {
            return Target([0xFF; 32]);
        }

        Target(result)
    }

    /// Convert to compact representation (for block header)
    pub fn compact(&self) -> u32 {
        let bytes = self.0;
        
        // Find first non-zero byte
        let mut size = 32;
        for (i, &b) in bytes.iter().enumerate() {
            if b != 0 {
                size = i;
                break;
            }
        }
        
        if size == 32 {
            return 0;
        }
        
        let exponent = (32 - size) as u32;
        let mantissa = ((bytes[size] as u32) << 16) |
                       ((bytes[size + 1] as u32) << 8) |
                       (bytes[size + 2] as u32);
        
        (exponent << 24) | mantissa
    }

    /// Create target from compact representation
    pub fn from_compact(compact: u32) -> Self {
        let exponent = (compact >> 24) & 0xFF;
        let mantissa = compact & 0x00FFFFFF;
        
        let mut bytes = [0u8; 32];
        
        if exponent <= 3 {
            bytes[31 - exponent as usize] = (mantissa >> 16) as u8;
            if exponent > 1 {
                bytes[32 - exponent as usize] = (mantissa >> 8) as u8;
            }
            if exponent > 2 {
                bytes[33 - exponent as usize] = mantissa as u8;
            }
        } else {
            let pos = 32 - exponent as usize;
            if pos < 32 {
                bytes[pos] = (mantissa >> 16) as u8;
                if pos + 1 < 32 {
                    bytes[pos + 1] = (mantissa >> 8) as u8;
                }
                if pos + 2 < 32 {
                    bytes[pos + 2] = mantissa as u8;
                }
            }
        }
        
        Target(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_left_8() {
        // Test case: shift left by 8 bits (one byte)
        let mut bytes = [0u8; 32];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[2] = 0x56;
        bytes[3] = 0x78;

        let target = Target(bytes);
        let shifted = target.shift_left(8);

        // After shift left by 8:
        // byte0 should be 0x12
        // byte1 should be 0x34
        // byte2 should be 0x56
        // byte3 should be 0x00
        // byte4 should be 0x78
        assert_eq!(shifted.0[0], 0x12);
        assert_eq!(shifted.0[1], 0x34);
        assert_eq!(shifted.0[2], 0x56);
        assert_eq!(shifted.0[3], 0x00);
        assert_eq!(shifted.0[4], 0x78);
    }

    #[test]
    fn test_shift_left_4() {
        // Test case: shift left by 4 bits
        let mut bytes = [0u8; 32];
        bytes[0] = 0xF0; // 11110000
        bytes[1] = 0x0F; // 00001111

        let target = Target(bytes);
        let shifted = target.shift_left(4);

        // After shift left by 4:
        // 0xF0 << 4 = 0x00 with carry 0x0F
        // 0x0F << 4 = 0xF0
        // So: byte0 = 0x00, byte1 = 0xFF, byte2 = 0x00
        assert_eq!(shifted.0[0], 0x00);
        assert_eq!(shifted.0[1], 0xFF);
        assert_eq!(shifted.0[2], 0x00);
    }

    #[test]
    fn test_scaled() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80; // 128
        
        let target = Target(bytes);
        
        // Scale up by 1.25
        let scaled_up = target.scaled(1.25);
        
        // Scale down by 0.75
        let scaled_down = target.scaled(0.75);
        
        // Should be different
        assert_ne!(target.0, scaled_up.0);
        assert_ne!(target.0, scaled_down.0);
    }

    #[test]
    fn test_is_met_by() {
        let target = Target([0x80; 32]);
        
        // Hash less than target
        let mut hash_less = [0x7F; 32];
        assert!(target.is_met_by(&hash_less));
        
        // Hash greater than target
        let mut hash_greater = [0x81; 32];
        assert!(!target.is_met_by(&hash_greater));
        
        // Hash equal to target
        let hash_equal = [0x80; 32];
        assert!(target.is_met_by(&hash_equal));
    }

    #[test]
    fn test_compact_roundtrip() {
        let target = Target([0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        
        let compact = target.compact();
        let recovered = Target::from_compact(compact);
        
        // Compact representation loses precision, but first bytes should match
        assert_eq!(target.0[0], recovered.0[0]);
        assert_eq!(target.0[1], recovered.0[1]);
        assert_eq!(target.0[2], recovered.0[2]);
    }
}