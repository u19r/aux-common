use std::{
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

use super::resources::{PendingCreation, TestFunction};

impl TestFunction {
    pub(crate) fn cleanup(&mut self) {
        assert!(
            self.reconcile_cleanup(),
            "owned resource cleanup unverified; inspect resource ledger"
        );
    }

    fn reconcile_cleanup(&mut self) -> bool {
        if !self.has_started_creation {
            return true;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut absent_since = None;
        while Instant::now() < deadline {
            self.observe_pending(deadline);
            self.delete_pass(deadline);
            if self.pending.is_none() && self.are_resources_absent(deadline) {
                let since = absent_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_secs(2) {
                    if self.persist_ledger("cleaned").is_ok() {
                        self.cleaned = true;
                        return true;
                    }
                    break;
                }
            } else {
                absent_since = None;
            }
            thread::sleep(
                Duration::from_millis(250).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        let _ = self.persist_ledger("cleanup-unverified");
        false
    }

    fn observe_pending(&mut self, deadline: Instant) {
        let observed = match self.pending {
            None => return,
            Some(PendingCreation::Function) => self
                .client
                .try_command_until(
                    &[
                        "lambda",
                        "get-function-configuration",
                        "--function-name",
                        &self.name,
                    ],
                    deadline,
                )
                .is_ok_and(|output| output.status.success()),
            Some(PendingCreation::Role) => self.role_name.as_ref().is_some_and(|name| {
                self.client
                    .try_command_until(&["iam", "get-role", "--role-name", name], deadline)
                    .is_ok_and(|output| output.status.success())
            }),
            Some(PendingCreation::Layer) => self
                .layer_versions(deadline)
                .is_some_and(|versions| !versions.is_empty()),
        };
        if observed {
            self.pending = None;
        }
    }

    fn delete_pass(&self, deadline: Instant) {
        let _ = self.client.try_command_until(
            &["lambda", "delete-function", "--function-name", &self.name],
            deadline,
        );
        if let Some(versions) = self.layer_versions(deadline) {
            for version in versions {
                let _ = self.client.try_command_until(
                    &[
                        "lambda",
                        "delete-layer-version",
                        "--layer-name",
                        &self.name,
                        "--version-number",
                        &version.to_string(),
                    ],
                    deadline,
                );
            }
        }
        if let Some(name) = &self.role_name {
            let _ = self.client.try_command_until(
                &[
                    "iam",
                    "detach-role-policy",
                    "--role-name",
                    name,
                    "--policy-arn",
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                ],
                deadline,
            );
            let _ = self
                .client
                .try_command_until(&["iam", "delete-role", "--role-name", name], deadline);
        }
        let _ = self.client.try_command_until(
            &[
                "logs",
                "delete-log-group",
                "--log-group-name",
                &format!("/aws/lambda/{}", self.name),
            ],
            deadline,
        );
    }

    fn are_resources_absent(&self, deadline: Instant) -> bool {
        let function = self.is_absent(
            &[
                "lambda",
                "get-function-configuration",
                "--function-name",
                &self.name,
            ],
            "ResourceNotFoundException",
            deadline,
        );
        let layers = self
            .layer_versions(deadline)
            .is_some_and(|versions| versions.is_empty());
        let role = self.role_name.as_ref().is_none_or(|name| {
            self.is_absent(
                &["iam", "get-role", "--role-name", name],
                "NoSuchEntity",
                deadline,
            )
        });
        let group = format!("/aws/lambda/{}", self.name);
        let logs = self
            .client
            .try_command_until(
                &[
                    "logs",
                    "describe-log-groups",
                    "--log-group-name-prefix",
                    &group,
                ],
                deadline,
            )
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| serde_json::from_slice::<Value>(&output.stdout).ok())
            .and_then(|value| {
                value["logGroups"]
                    .as_array()
                    .map(|groups| !groups.iter().any(|item| item["logGroupName"] == group))
            })
            .unwrap_or(false);
        function && layers && role && logs
    }

    fn is_absent(&self, args: &[&str], category: &str, deadline: Instant) -> bool {
        self.client
            .try_command_until(args, deadline)
            .is_ok_and(|output| {
                !output.status.success()
                    && String::from_utf8_lossy(&output.stderr).contains(category)
            })
    }

    fn layer_versions(&self, deadline: Instant) -> Option<Vec<u64>> {
        let output = self
            .client
            .try_command_until(
                &["lambda", "list-layer-versions", "--layer-name", &self.name],
                deadline,
            )
            .ok()?;
        if !output.status.success() {
            return String::from_utf8_lossy(&output.stderr)
                .contains("ResourceNotFoundException")
                .then(Vec::new);
        }
        let value: Value = serde_json::from_slice(&output.stdout).ok()?;
        value["LayerVersions"]
            .as_array()?
            .iter()
            .map(|version| version["Version"].as_u64())
            .collect()
    }
}

impl Drop for TestFunction {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.reconcile_cleanup();
        }
    }
}
