use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context, Poll},
};

pub(crate) struct HandlerPanic;

/// Both handler execution and claim publication cross caller-owned futures.
pub(crate) struct PanicSafeFuture<F> {
    future: Pin<Box<F>>,
}

impl<F> PanicSafeFuture<F> {
    pub(crate) fn new(future: F) -> Self {
        Self {
            future: Box::pin(future),
        }
    }
}

impl<F, T, E> Future for PanicSafeFuture<F>
where F: Future<Output = Result<T, E>> + Unpin
{
    type Output = Result<Result<T, E>, HandlerPanic>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let future = self.get_mut();
        match catch_unwind(AssertUnwindSafe(|| future.future.as_mut().poll(context))) {
            Ok(Poll::Ready(result)) => Poll::Ready(Ok(result)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(HandlerPanic)),
        }
    }
}
