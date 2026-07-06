use std::collections::HashMap;

use authz_types::{AcrLevel, ChallengeType, SessionContext, StepUpConfig, StepUpRule};

use crate::{StepUpEvaluator, StepUpResult};

#[test]
fn missing_session_returns_challenge_for_required_rule() {
    let rules = vec![StepUpRule::require_acr(
        "rule_mfa",
        "Require MFA",
        AcrLevel::MultiFactor,
    )];
    let config = HashMap::new();
    let evaluator = StepUpEvaluator::new(&rules, &config, Some("rule_mfa"));

    let result = evaluator.evaluate("document", "delete", None, false);

    let StepUpResult::ChallengeRequired(challenge) = result else {
        panic!("missing session should require a challenge");
    };
    assert_eq!(challenge.challenge_type, ChallengeType::Mfa);
}

#[test]
fn api_key_can_skip_rule_that_does_not_apply_to_api_keys() {
    let mut rule = StepUpRule::require_acr("rule_mfa", "Require MFA", AcrLevel::MultiFactor);
    rule.applies_to_api_keys = false;
    let rules = vec![rule];
    let config = HashMap::new();
    let evaluator = StepUpEvaluator::new(&rules, &config, Some("rule_mfa"));

    let result = evaluator.evaluate("document", "delete", None, true);

    assert!(matches!(result, StepUpResult::Satisfied));
}

#[test]
fn action_specific_rule_overrides_default_rule() {
    let rules = vec![
        StepUpRule::require_acr("rule_mfa", "Require MFA", AcrLevel::MultiFactor),
        StepUpRule::require_acr("rule_pwd", "Require password", AcrLevel::SingleFactor),
    ];
    let mut config = HashMap::new();
    config.insert(
        "document".to_string(),
        StepUpConfig {
            default_rule: Some("rule_mfa".to_string()),
            action_rules: HashMap::from([("read".to_string(), "rule_pwd".to_string())]),
        },
    );
    let session = SessionContext::password_only(1_800_000_000);
    let evaluator = StepUpEvaluator::new(&rules, &config, None);

    let result = evaluator.evaluate("document", "read", Some(&session), false);

    assert!(matches!(result, StepUpResult::Satisfied));
}
