use std::{env, net::SocketAddr, time::Duration};

use url::Url;

use super::{
    constants::{HTTP_ENDPOINT_ENV, READY_PATH, RUNTIME_API_ENV, SHUTDOWN_GRACE},
    error::LambdaWebRuntimeError,
};

pub struct LambdaWebEnvironment {
    listen_address: SocketAddr,
    pub(crate) ready_url: Url,
}

impl LambdaWebEnvironment {
    /// Read the reserved addresses; ordinary processes return `None`.
    pub fn load() -> Result<Option<Self>, LambdaWebRuntimeError> {
        let http = read_address(
            HTTP_ENDPOINT_ENV,
            LambdaWebRuntimeError::InvalidListenAddress,
        )?;
        let runtime = read_address(
            RUNTIME_API_ENV,
            LambdaWebRuntimeError::InvalidRuntimeAddress,
        )?;
        Self::parse(http.as_deref(), runtime.as_deref())
    }

    /// Validate both addresses without reading or mutating the process
    /// environment.
    pub fn parse(
        http: Option<&str>,
        runtime: Option<&str>,
    ) -> Result<Option<Self>, LambdaWebRuntimeError> {
        let (http, runtime) = match (http, runtime) {
            (None, None) => return Ok(None),
            (None, Some(_)) => return Err(LambdaWebRuntimeError::InvalidListenAddress),
            (Some(_), None) => return Err(LambdaWebRuntimeError::InvalidRuntimeAddress),
            (Some(http), Some(runtime)) => (http, runtime),
        };
        let listen_address = http
            .parse()
            .map_err(|_| LambdaWebRuntimeError::InvalidListenAddress)?;
        let ready_url = parse_ready_url(runtime)?;
        Ok(Some(Self {
            listen_address,
            ready_url,
        }))
    }

    /// Return the validated address that the server must bind.
    #[must_use]
    pub fn listen_address(&self) -> SocketAddr {
        self.listen_address
    }

    /// Leave time inside Lambda's one-second SIGTERM cleanup window.
    #[must_use]
    pub fn shutdown_grace(&self) -> Duration {
        SHUTDOWN_GRACE
    }
}

fn read_address(
    name: &str,
    error: LambdaWebRuntimeError,
) -> Result<Option<String>, LambdaWebRuntimeError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(error),
    }
}

fn parse_ready_url(runtime: &str) -> Result<Url, LambdaWebRuntimeError> {
    let mut url = Url::parse(&format!("http://{runtime}"))
        .map_err(|_| LambdaWebRuntimeError::InvalidRuntimeAddress)?;
    if !has_valid_authority(runtime, &url) {
        return Err(LambdaWebRuntimeError::InvalidRuntimeAddress);
    }
    url.set_path(READY_PATH);
    Ok(url)
}

fn has_valid_authority(runtime: &str, url: &Url) -> bool {
    let has_port = runtime
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok_and(|port| port != 0));
    has_port
        && url.host_str().is_some()
        && url.path() == "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}
