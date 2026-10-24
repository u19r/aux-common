use bytes::Bytes;
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{LifecycleError, constants::LAMBDA_IPC_MAX_MESSAGE_BYTES};

pub(super) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Bytes, crate::EncodeError> {
    crate::batch::encode_json(value, LAMBDA_IPC_MAX_MESSAGE_BYTES)
}

pub(super) async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, LifecycleError> {
    let size = stream.read_u32().await.map_err(io_error)? as usize;
    if size == 0 || size > LAMBDA_IPC_MAX_MESSAGE_BYTES {
        return Err(LifecycleError::IpcProtocolViolation {
            reason: "Lambda IPC frame length is invalid",
        });
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await.map_err(io_error)?;
    Ok(bytes)
}

pub(super) async fn write_frame(
    stream: &mut TcpStream,
    bytes: &[u8],
) -> Result<(), LifecycleError> {
    let size = u32::try_from(bytes.len()).map_err(|_| LifecycleError::IpcProtocolViolation {
        reason: "Lambda IPC frame length is invalid",
    })?;
    stream.write_u32(size).await.map_err(io_error)?;
    stream.write_all(bytes).await.map_err(io_error)
}

fn io_error(_: std::io::Error) -> LifecycleError {
    LifecycleError::IpcUnavailable {
        reason: "Lambda IPC connection failed",
    }
}
