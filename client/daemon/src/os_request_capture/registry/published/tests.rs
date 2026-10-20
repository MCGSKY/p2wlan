//! Pure source-storage controls, without native observations or owners.
use super::*;

#[test]
fn published_history_keeps_one_ordered_bounded_prefix_across_readers() {
    let mut original = Published::new(2).unwrap();
    let reader = original.clone();
    original.push(11).unwrap();
    let frozen = reader.iter();
    original.push(22).unwrap();
    assert_eq!(frozen.copied().collect::<Vec<_>>(), vec![11]);
    assert_eq!(reader.iter().copied().collect::<Vec<_>>(), vec![11, 22]);
    assert_eq!(reader.get(0), Some(&11));
    assert_eq!(reader.get(2), None);
    assert!(matches!(original.push(33), Err(CaptureFailure::Capacity)));
    assert!(matches!(
        original.try_reserve(1),
        Err(CaptureFailure::Capacity)
    ));
    assert_eq!(original.len(), 2);
}

#[test]
fn published_first_fact_shares_the_sole_cell_and_cannot_replace_first_negative() {
    let mut original = First::new();
    let mut reader = original.clone();
    let before = reader.as_ref().copied();
    assert!(before.is_none());
    assert_eq!(original.set(false), Ok(()));
    assert_eq!(reader.as_ref(), Some(&false));
    assert_eq!(original.set(true), Err(true));
    assert_eq!(reader.as_ref(), Some(&false));
    assert!(before.is_none());
    assert!(!reader.get_or_insert_with(|| panic!("first value must not be recaptured")));
}

#[test]
fn published_storage_allocation_refusal_cannot_publish_membership() {
    assert!(matches!(
        Published::<u64>::new(usize::MAX),
        Err(CaptureFailure::Capacity)
    ));
    let mut empty = Published::new(0).unwrap();
    assert!(matches!(empty.push(7u8), Err(CaptureFailure::Capacity)));
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.iter().count(), 0);
}
