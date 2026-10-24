use javascript::{JsSourceOrder, protocol::GuestJob};
use rquickjs::{Ctx, Function, Value, function::Args};

pub(super) fn invoke_function<'js>(ctx: &Ctx<'js>, job: &GuestJob) -> rquickjs::Result<Value<'js>> {
    let values = job
        .arguments
        .iter()
        .map(|v| ctx.json_parse(v.get()))
        .collect::<rquickjs::Result<Vec<Value>>>()?;
    if matches!(job.source_order, JsSourceOrder::BeforeBindings) {
        ctx.eval::<(), _>(job.source.as_bytes())?;
    }
    for binding in &job.bindings {
        ctx.globals().set(
            binding.name.as_str(),
            values[binding.argument_index].clone(),
        )?;
    }
    if matches!(job.source_order, JsSourceOrder::AfterBindings) {
        ctx.eval::<(), _>(job.source.as_bytes())?;
    }
    let function: Function = ctx.eval(job.function.as_bytes())?;
    let mut arguments = Args::new(ctx.clone(), values.len());
    for value in values {
        arguments.push_arg(value)?;
    }
    function.call_arg(arguments)
}
