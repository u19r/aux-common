use std::collections::HashMap;

use authz_types::{
    AcrLevel, AuthzChallenge, ChallengeType, SessionContext, StepUpConfig, StepUpRule,
};
use chrono::Utc;

#[derive(Debug, Clone)]
pub enum StepUpResult {
    Satisfied,
    ChallengeRequired(AuthzChallenge),
}

pub struct StepUpEvaluator<'a> {
    rules: HashMap<&'a str, &'a StepUpRule>,
    resource_config: &'a HashMap<String, StepUpConfig>,
    default_rule: Option<&'a str>,
}

impl<'a> StepUpEvaluator<'a> {
    pub fn new(
        rules: &'a [StepUpRule],
        resource_config: &'a HashMap<String, StepUpConfig>,
        default_rule: Option<&'a str>,
    ) -> Self {
        let rules = rules
            .iter()
            .map(|rule| (rule.rule_id.as_str(), rule))
            .collect();
        Self {
            rules,
            resource_config,
            default_rule,
        }
    }

    pub fn evaluate(
        &self,
        resource_type: &str,
        action: &str,
        session: Option<&SessionContext>,
        is_api_key: bool,
    ) -> StepUpResult {
        self.evaluate_at(
            resource_type,
            action,
            session,
            is_api_key,
            Utc::now().timestamp(),
        )
    }

    pub fn evaluate_at(
        &self,
        resource_type: &str,
        action: &str,
        session: Option<&SessionContext>,
        is_api_key: bool,
        now_seconds: i64,
    ) -> StepUpResult {
        let Some(rule_id) = self.find_applicable_rule(resource_type, action) else {
            return StepUpResult::Satisfied;
        };
        let Some(rule) = self.rules.get(rule_id) else {
            return StepUpResult::ChallengeRequired(Self::challenge_for_missing_rule(rule_id));
        };
        let rule = *rule;

        if is_api_key && !rule.applies_to_api_keys {
            return StepUpResult::Satisfied;
        }

        let Some(session) = session else {
            return StepUpResult::ChallengeRequired(self.challenge_for_missing_session(rule));
        };

        self.evaluate_rule(rule, session, now_seconds)
    }

    fn find_applicable_rule(&self, resource_type: &str, action: &str) -> Option<&str> {
        if let Some(config) = self.resource_config.get(resource_type) {
            if let Some(rule_id) = config.action_rules.get(action) {
                return Some(rule_id.as_str());
            }
            if let Some(rule_id) = &config.default_rule {
                return Some(rule_id.as_str());
            }
        }
        self.default_rule
    }

    fn evaluate_rule(
        &self,
        rule: &StepUpRule,
        session: &SessionContext,
        now_seconds: i64,
    ) -> StepUpResult {
        if !session.acr.satisfies(rule.required_acr) {
            let challenge_type = self.select_challenge_type(rule, Some(session));
            let challenge =
                AuthzChallenge::for_step_up(&rule.rule_id, rule.required_acr, challenge_type)
                    .with_www_authenticate(Self::build_www_authenticate(
                        rule.required_acr,
                        rule.max_auth_age_seconds,
                    ));
            return StepUpResult::ChallengeRequired(challenge);
        }

        if let Some(max_age) = rule.max_auth_age_seconds
            && !session.is_auth_recent_at(now_seconds, max_age)
        {
            let challenge =
                AuthzChallenge::re_authenticate(&rule.rule_id, max_age).with_www_authenticate(
                    Self::build_www_authenticate(AcrLevel::RecentAuth, Some(max_age)),
                );
            return StepUpResult::ChallengeRequired(challenge);
        }

        if let Some(max_mfa_age) = rule.max_mfa_age_seconds
            && !session.is_mfa_recent_at(now_seconds, max_mfa_age)
        {
            let challenge = AuthzChallenge::for_step_up(
                &rule.rule_id,
                AcrLevel::MultiFactor,
                ChallengeType::Mfa,
            )
            .with_www_authenticate(Self::build_www_authenticate(
                AcrLevel::MultiFactor,
                Some(max_mfa_age),
            ));
            return StepUpResult::ChallengeRequired(challenge);
        }

        if !rule.required_amr.is_empty() {
            let has_required = rule.required_amr.iter().any(|amr| session.has_amr(amr));
            if !has_required {
                let challenge_type = self.amr_to_challenge_type(&rule.required_amr);
                let challenge =
                    AuthzChallenge::for_step_up(&rule.rule_id, rule.required_acr, challenge_type)
                        .with_www_authenticate(Self::build_www_authenticate(
                            rule.required_acr,
                            rule.max_auth_age_seconds,
                        ));
                return StepUpResult::ChallengeRequired(challenge);
            }
        }

        StepUpResult::Satisfied
    }

    fn select_challenge_type(
        &self,
        rule: &StepUpRule,
        session: Option<&SessionContext>,
    ) -> ChallengeType {
        if !rule.required_amr.is_empty() {
            return self.amr_to_challenge_type(&rule.required_amr);
        }
        match rule.required_acr {
            AcrLevel::None | AcrLevel::SingleFactor => ChallengeType::ReAuthenticate,
            AcrLevel::MultiFactor => {
                if let Some(session) = session
                    && session.has_amr("otp")
                {
                    return ChallengeType::Totp;
                }
                ChallengeType::Mfa
            }
            AcrLevel::HardwareToken => ChallengeType::Fido2,
            AcrLevel::RecentAuth => ChallengeType::ReAuthenticate,
        }
    }

    fn amr_to_challenge_type(&self, amr_values: &[String]) -> ChallengeType {
        for amr in amr_values {
            match amr.as_str() {
                "hwk" | "fido2" | "webauthn" => return ChallengeType::Fido2,
                "otp" | "totp" => return ChallengeType::Totp,
                "sms" => return ChallengeType::SmsOtp,
                "email" => return ChallengeType::EmailOtp,
                "pwd" | "password" => return ChallengeType::ReAuthenticate,
                _ => continue,
            }
        }
        ChallengeType::Mfa
    }

    fn challenge_for_missing_session(&self, rule: &StepUpRule) -> AuthzChallenge {
        let challenge_type = self.select_challenge_type(rule, None);
        AuthzChallenge::for_step_up(&rule.rule_id, rule.required_acr, challenge_type)
            .with_www_authenticate(Self::build_www_authenticate(
                rule.required_acr,
                rule.max_auth_age_seconds,
            ))
    }

    fn challenge_for_missing_rule(rule_id: &str) -> AuthzChallenge {
        AuthzChallenge::for_step_up(rule_id, AcrLevel::RecentAuth, ChallengeType::Custom)
            .with_www_authenticate(Self::build_www_authenticate(AcrLevel::RecentAuth, None))
    }

    fn build_www_authenticate(required_acr: AcrLevel, max_age: Option<u64>) -> String {
        let mut parts = vec![r#"Bearer error="insufficient_user_authentication""#.to_string()];
        parts.push(format!(r#" acr_values="{}""#, required_acr.to_urn()));
        if let Some(age) = max_age {
            parts.push(format!(r#" max_age={age}"#));
        }
        parts.join(",")
    }
}
