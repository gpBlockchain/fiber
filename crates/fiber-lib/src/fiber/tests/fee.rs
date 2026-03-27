use crate::fiber::fee::{
    calculate_commitment_tx_fee, calculate_fee_with_base, calculate_shutdown_tx_fee,
    calculate_tlc_forward_fee,
};
use crate::fiber::channel::{
    DEFAULT_COMMITMENT_FEE_RATE, DEFAULT_FEE_RATE,
};
use crate::ckb::contracts::get_script_by_contract;
use crate::ckb::contracts::Contract;

#[test]
fn test_calculate_fee_with_base_simple() {
    // 1% fee on 1000 amount = 10
    let result = calculate_fee_with_base(1000, 10000, 1_000_000).unwrap();
    assert_eq!(result, 10);
}

#[test]
fn test_calculate_fee_with_base_zero_fee() {
    // 0% fee = 0
    let result = calculate_fee_with_base(1000, 0, 1_000_000).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn test_calculate_fee_with_base_round_up() {
    // Fee that doesn't divide evenly should round up
    // 1% fee on 1001 amount = 10.01 -> rounds to 11
    let result = calculate_fee_with_base(1001, 10000, 1_000_000).unwrap();
    assert_eq!(result, 11);
}

#[test]
fn test_calculate_fee_with_base_exact_division() {
    // Fee that divides evenly - no rounding needed
    // 1% fee on 1000000 amount = 10000 exactly
    let result = calculate_fee_with_base(1000000, 10000, 1_000_000).unwrap();
    assert_eq!(result, 10000);
}

#[test]
fn test_calculate_fee_with_base_overflow() {
    // Test overflow scenario with very large values
    let result = calculate_fee_with_base(u128::MAX, u128::MAX, 1);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("overflow"));
}

#[test]
fn test_calculate_fee_with_base_large_values() {
    // Test with realistically large values
    // 1000 ppm (0.1%) on 1 trillion amount
    let result = calculate_fee_with_base(1_000_000_000_000, 1000, 1_000_000).unwrap();
    assert_eq!(result, 1_000_000_000); // 0.1% of 1T = 1B
}

#[test]
fn test_calculate_tlc_forward_fee_simple() {
    // 1000 ppm (0.1%) on 1000000 amount = 1000
    let result = calculate_tlc_forward_fee(1000000, 1000).unwrap();
    assert_eq!(result, 1000);
}

#[test]
fn test_calculate_tlc_forward_fee_zero() {
    // Zero fee should return 0
    let result = calculate_tlc_forward_fee(1000000, 0).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn test_calculate_tlc_forward_fee_typical() {
    // Typical fee: 5000 ppm (0.5%) on 100000000 amount = 500000
    let result = calculate_tlc_forward_fee(100_000_000, 5000).unwrap();
    assert_eq!(result, 500_000);
}

#[test]
fn test_calculate_tlc_forward_fee_small_amount() {
    // Small amount with fee that rounds up
    // 100 ppm (0.01%) on 1000 amount = 0.1 -> rounds to 1
    let result = calculate_tlc_forward_fee(1000, 100).unwrap();
    assert_eq!(result, 1);
}

#[test]
fn test_calculate_commitment_tx_fee_basic() {
    // Test basic fee calculation for CKB (no UDT)
    let fee = calculate_commitment_tx_fee(DEFAULT_COMMITMENT_FEE_RATE, &None);
    // Fee should be > 0
    assert!(fee > 0);
}

#[test]
fn test_calculate_commitment_tx_fee_different_rates() {
    // Higher rate should give higher fee
    let fee_low = calculate_commitment_tx_fee(1000, &None);
    let fee_high = calculate_commitment_tx_fee(5000, &None);
    assert!(fee_high > fee_low);
}

#[test]
fn test_calculate_shutdown_tx_fee_basic() {
    // Create dummy scripts for shutdown
    let script_a = get_script_by_contract(Contract::Secp256k1Lock, &[0u8; 32]);
    let script_b = get_script_by_contract(Contract::Secp256k1Lock, &[1u8; 32]);

    let fee = calculate_shutdown_tx_fee(DEFAULT_FEE_RATE, &None, (script_a, script_b));
    // Fee should be > 0
    assert!(fee > 0);
}

#[test]
fn test_calculate_shutdown_tx_fee_different_rates() {
    // Create dummy scripts for shutdown
    let script_a = get_script_by_contract(Contract::Secp256k1Lock, &[0u8; 32]);
    let script_b = get_script_by_contract(Contract::Secp256k1Lock, &[1u8; 32]);

    // Higher rate should give higher fee
    let fee_low = calculate_shutdown_tx_fee(1000, &None, (script_a.clone(), script_b.clone()));
    let fee_high = calculate_shutdown_tx_fee(5000, &None, (script_a, script_b));
    assert!(fee_high > fee_low);
}
