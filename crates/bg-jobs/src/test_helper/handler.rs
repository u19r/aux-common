use crate::{ExecutionContext, HandlerFuture, JobHandler, JobOutcome, OutcomeCode};

pub(crate) struct CompletingHandler;

impl JobHandler for CompletingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async {
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("completed").expect("test outcome is valid"),
            ))
        })
    }
}
