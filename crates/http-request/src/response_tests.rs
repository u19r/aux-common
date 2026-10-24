use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use http::HeaderMap;
use reqwest::{StatusCode, Url};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

use crate::{HttpClient, HttpRequestError, HttpRequestErrorKind, HttpResponse};

#[tokio::test]
async fn given_mock_response_body_limits_when_streaming_then_only_admitted_bytes_are_exposed_and_errors_end_the_stream()
 {
    for limit in [None, Some(0), Some(3), Some(8)] {
        for body in [b"".as_slice(), b"abc".as_slice(), b"abcdefgh".as_slice()] {
            let response = HttpResponse::from_mock(
                StatusCode::OK,
                HeaderMap::new(),
                body.to_vec(),
                Url::parse("https://example.test/body").unwrap(),
            );
            let mut stream = response.with_max_body_size(limit).bytes_stream();
            let first = stream.next().await.unwrap();
            if let Some(max) = limit
                && body.len() > max
            {
                assert!(
                    matches!(first, Err(HttpRequestError::ResponseTooLarge { size, max: actual }) if size == body.len() && actual == max)
                );
            } else {
                assert_eq!(first.unwrap().as_ref(), body);
            }
            assert!(stream.next().await.is_none());
        }
    }
}

#[tokio::test]
async fn given_native_chunked_response_when_streaming_crosses_the_cumulative_limit_then_no_oversized_chunk_or_further_body_read_is_exposed()
 {
    for limit in [None, Some(5), Some(7)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let next_chunk = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let advance = next_chunk.clone();
        let close = finish.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n").await.unwrap();
            advance.notified().await;
            socket.write_all(b"4\r\ndefg\r\n").await.unwrap();
            close.notified().await;
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });
        let client = HttpClient::builder().build().unwrap();
        let response = client
            .get(format!("http://{address}/body"))
            .send()
            .await
            .unwrap();
        let mut stream = response.with_max_body_size(limit).bytes_stream();
        assert_eq!(stream.next().await.unwrap().unwrap().as_ref(), b"abc");
        next_chunk.notify_one();
        let next = stream.next().await.unwrap();
        if limit == Some(5) {
            assert!(matches!(
                next,
                Err(HttpRequestError::ResponseTooLarge { size: 7, max: 5 })
            ));
            assert!(
                tokio::time::timeout(Duration::from_secs(1), stream.next())
                    .await
                    .unwrap()
                    .is_none(),
                "a rejected stream must end without waiting for provider EOF"
            );
            finish.notify_one();
        } else {
            assert_eq!(next.unwrap().as_ref(), b"defg");
            finish.notify_one();
            assert!(stream.next().await.is_none());
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn given_a_native_truncated_body_when_streaming_then_transport_failure_is_distinct_from_a_size_rejection()
 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_headers(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nab")
            .await
            .unwrap();
    });
    let client = HttpClient::builder().build().unwrap();
    let mut stream = client
        .get(format!("http://{address}/body"))
        .send()
        .await
        .unwrap()
        .bytes_stream();
    let mut failure = None;
    while let Some(chunk) = stream.next().await {
        if let Err(error) = chunk {
            failure = Some(error);
            break;
        }
    }
    assert!(matches!(failure, Some(HttpRequestError::ResponseBody)));
    assert!(stream.next().await.is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn given_a_native_body_that_never_arrives_when_the_request_deadline_expires_then_the_uncapped_stream_reports_timeout_and_ends()
 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let finish = Arc::new(Notify::new());
    let close = finish.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_headers(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        close.notified().await;
    });
    let client = HttpClient::builder()
        .with_reqwest_builder(|builder| builder.timeout(Duration::from_millis(200)))
        .build()
        .unwrap();
    let mut stream = client
        .get(format!("http://{address}/body"))
        .send()
        .await
        .unwrap()
        .with_max_body_size(None)
        .bytes_stream();
    let error = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error,
        HttpRequestError::Transport {
            kind: HttpRequestErrorKind::Timeout
        }
    ));
    assert!(stream.next().await.is_none());
    finish.notify_one();
    server.await.unwrap();
}

#[tokio::test]
async fn given_a_streaming_client_when_a_download_keeps_progressing_then_the_idle_deadline_resets_and_a_later_stall_times_out()
 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let finish = Arc::new(Notify::new());
    let close = finish.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_headers(&mut socket).await;
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            socket.write_all(b"1\r\na\r\n").await.unwrap();
        }
        close.notified().await;
    });
    let client = crate::HttpClientBuilder::for_streaming()
        .with_reqwest_builder(|builder| builder.read_timeout(Duration::from_millis(200)))
        .build()
        .unwrap();
    let mut stream = client
        .get(format!("http://{address}/body"))
        .send()
        .await
        .unwrap()
        .with_max_body_size(None)
        .bytes_stream();
    for _ in 0..4 {
        assert_eq!(stream.next().await.unwrap().unwrap().as_ref(), b"a");
    }
    let error = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error,
        HttpRequestError::Transport {
            kind: HttpRequestErrorKind::Timeout
        }
    ));
    assert!(stream.next().await.is_none());
    finish.notify_one();
    server.await.unwrap();
}

async fn read_request_headers(socket: &mut TcpStream) {
    let mut request = [0; 1024];
    let mut length = 0;
    loop {
        assert!(
            length < request.len(),
            "request headers exceed fixture capacity"
        );
        let count = socket.read(&mut request[length..]).await.unwrap();
        assert_ne!(count, 0, "peer closed before sending request headers");
        length += count;
        if request[..length]
            .windows(4)
            .any(|bytes| bytes == b"\r\n\r\n")
        {
            return;
        }
    }
}
