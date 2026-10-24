use super::state::ServiceExtrema;

#[test]
fn given_tied_minimums_and_maximums_when_excluding_each_target_then_extrema_match_scan() {
    let services = [1_u128, 5, 5, 10];
    let mut extrema = ServiceExtrema::default();
    for (primary_index, service) in services.into_iter().enumerate() {
        extrema.insert(primary_index, service);
    }

    for target_index in 0..services.len() {
        for service in 0_u128..=12 {
            for bound in 0_u128..=12 {
                let expected = services
                    .iter()
                    .enumerate()
                    .filter(|(primary_index, _)| *primary_index != target_index)
                    .all(|(_, other)| service.abs_diff(*other) <= bound);
                assert_eq!(
                    extrema.allows(target_index, service, bound),
                    expected,
                    "target={target_index} service={service} bound={bound}"
                );
            }
        }
    }
}
