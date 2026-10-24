use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use serde_json::json;

use super::cli::AwsTestClient;

// CLI stdout is private: Lambda configuration includes the IPC secret.
// The persistent ledger contains only resource names and proof state.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PendingCreation {
    Role,
    Layer,
    Function,
}

pub(crate) struct TestFunction {
    pub(super) client: AwsTestClient,
    pub(super) name: String,
    pub(super) role_name: Option<String>,
    pub(super) pending: Option<PendingCreation>,
    pub(super) has_started_creation: bool,
    pub(super) receipt_dir: PathBuf,
    pub(super) started_ms: u64,
    pub(super) cleaned: bool,
}
impl TestFunction {
    pub(crate) fn prepare() -> Self {
        let mut resources = Self {
            client: AwsTestClient::from_env(),
            name: format!("buffered-writes-{}", uuid::Uuid::now_v7()),
            role_name: None,
            pending: None,
            has_started_creation: false,
            receipt_dir: PathBuf::from(
                std::env::var("BUFFERED_WRITES_LAMBDA_RECEIPT_DIR")
                    .expect("explicit receipt directory"),
            ),
            started_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap(),
            cleaned: false,
        };
        resources.receipt_dir = resources.receipt_dir.join(&resources.name);
        std::fs::create_dir_all(&resources.receipt_dir).unwrap();
        resources.write_ledger("preflight");
        resources.client.aws(&["sts", "get-caller-identity"]);
        resources
    }

    pub(super) fn persist_ledger(&self, state: &str) -> std::io::Result<()> {
        let ledger = json!({"state":state, "function":self.name, "owned_role":self.role_name,
            "layer_name":self.name, "log_group":format!("/aws/lambda/{}",self.name), "region":self.client.region,
            "started_ms":self.started_ms, "pending_creation":self.pending});
        std::fs::write(
            self.receipt_dir.join("resources.json"),
            serde_json::to_vec_pretty(&ledger).unwrap(),
        )
    }

    pub(super) fn write_ledger(&self, state: &str) {
        self.persist_ledger(state)
            .expect("resource ledger write failed");
    }

    fn execution_role(&mut self) -> String {
        if let Ok(arn) = std::env::var("BUFFERED_WRITES_LAMBDA_ROLE_ARN") {
            return arn;
        }
        let name = self.name.clone();
        self.role_name = Some(name.clone());
        self.pending = Some(PendingCreation::Role);
        self.has_started_creation = true;
        self.write_ledger("creating-role");
        let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]})
        .to_string();
        let role = self.client.aws(&[
            "iam",
            "create-role",
            "--role-name",
            &name,
            "--assume-role-policy-document",
            &trust,
        ]);
        self.pending = None;
        self.client.aws(&[
            "iam",
            "attach-role-policy",
            "--role-name",
            &name,
            "--policy-arn",
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        ]);
        role["Role"]["Arn"]
            .as_str()
            .expect("execution role ARN")
            .to_owned()
    }

    pub(crate) fn create(&mut self) {
        let archive = validate_archive("BUFFERED_WRITES_LAMBDA_ZIP", "bootstrap");
        let extension = validate_archive(
            "BUFFERED_WRITES_LAMBDA_LAYER_ZIP",
            "extensions/lambda-extension",
        );
        let role = self.execution_role();
        let layer = self.publish_layer(&extension);
        let environment =
            json!({"Variables":{"BUFFERED_WRITES_IPC_TOKEN":uuid::Uuid::now_v7().to_string(),
            "BUFFERED_WRITES_FLUSH_AGE_MS":"1500"}})
            .to_string();
        self.pending = Some(PendingCreation::Function);
        self.has_started_creation = true;
        self.write_ledger("creating-function");
        let args = [
            "lambda",
            "create-function",
            "--function-name",
            &self.name,
            "--runtime",
            "provided.al2023",
            "--handler",
            "bootstrap",
            "--architectures",
            "arm64",
            "--role",
            &role,
            "--zip-file",
            &archive,
            "--layers",
            &layer,
            "--timeout",
            "8",
            "--memory-size",
            "256",
            "--logging-config",
            "{\"LogFormat\":\"Text\"}",
            "--environment",
            &environment,
        ];
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            self.pending = Some(PendingCreation::Function);
            self.write_ledger("creating-function");
            let output = self.client.command(&args);
            if output.status.success() {
                self.pending = None;
                break;
            }
            // IAM propagation is the only retried failure. A transport-unknown
            // create is reconciled by name; other errors fail without replay.
            let existing = self.client.command(&[
                "lambda",
                "get-function-configuration",
                "--function-name",
                &self.name,
            ]);
            if existing.status.success() {
                self.pending = None;
                break;
            }
            let is_role_propagating =
                String::from_utf8_lossy(&output.stderr).contains("cannot be assumed by Lambda");
            if is_role_propagating {
                self.pending = None;
            }
            assert!(
                is_role_propagating && Instant::now() < deadline,
                "Lambda create failed; resource ledger preserves cleanup identity"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
        self.client.aws(&[
            "lambda",
            "wait",
            "function-active-v2",
            "--function-name",
            &self.name,
        ]);
        self.client.aws(&[
            "lambda",
            "put-function-concurrency",
            "--function-name",
            &self.name,
            "--reserved-concurrent-executions",
            "1",
        ]);
        self.write_ledger("active");
    }

    fn publish_layer(&mut self, archive: &str) -> String {
        self.pending = Some(PendingCreation::Layer);
        self.has_started_creation = true;
        self.write_ledger("publishing-layer");
        let layer = self.client.aws(&[
            "lambda",
            "publish-layer-version",
            "--layer-name",
            &self.name,
            "--zip-file",
            archive,
            "--compatible-runtimes",
            "provided.al2023",
            "--compatible-architectures",
            "arm64",
        ]);
        self.pending = None;
        layer["LayerVersionArn"]
            .as_str()
            .expect("layer version ARN")
            .to_owned()
    }
}

fn validate_archive(variable: &str, entry: &str) -> String {
    let path = PathBuf::from(std::env::var(variable).expect("explicit Lambda function/layer ZIPs"));
    assert!(path.is_file());
    let listing = std::process::Command::new("unzip")
        .args(["-Z1", path.to_str().unwrap()])
        .output()
        .expect("unzip required to validate package layout");
    assert!(listing.status.success());
    assert_eq!(
        String::from_utf8(listing.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        vec![entry],
        "function and external extension must be separate artifacts"
    );
    format!("fileb://{}", path.canonicalize().unwrap().display())
}
