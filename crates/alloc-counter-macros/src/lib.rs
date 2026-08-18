#![doc(hidden)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Expr, ExprLit, ItemFn, Lit, LitStr, Meta, MetaNameValue, Token, parse_macro_input,
    punctuated::Punctuated,
};

#[proc_macro_attribute]
pub fn count_allocations(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args with Punctuated::<Meta, Token![,]>::parse_terminated);
    let label = match parse_label(args) {
        Ok(label) => label,
        Err(error) => return error.into_compile_error().into(),
    };

    let mut test_fn = parse_macro_input!(input as ItemFn);
    let fn_ident = test_fn.sig.ident.clone();
    let original_body = test_fn.block;
    let label_expr = if let Some(value) = label {
        quote! { Some(#value) }
    } else {
        quote! { None }
    };

    let wrapped_body_tokens = if test_fn.sig.asyncness.is_some() {
        quote! {{
            let __alloc_counter_guard = ::alloc_counter::AllocationGuard::start(
                module_path!(),
                stringify!(#fn_ident),
                file!(),
                line!(),
                #label_expr,
            );
            let __alloc_counter_result = (async move #original_body).await;
            let __alloc_counter_report = __alloc_counter_guard.finish();
            ::alloc_counter::emit_report(&__alloc_counter_report);
            __alloc_counter_result
        }}
    } else {
        quote! {{
            let __alloc_counter_guard = ::alloc_counter::AllocationGuard::start(
                module_path!(),
                stringify!(#fn_ident),
                file!(),
                line!(),
                #label_expr,
            );
            let __alloc_counter_result = (|| #original_body)();
            let __alloc_counter_report = __alloc_counter_guard.finish();
            ::alloc_counter::emit_report(&__alloc_counter_report);
            __alloc_counter_result
        }}
    };

    let wrapped_body = match syn::parse2(wrapped_body_tokens) {
        Ok(body) => body,
        Err(err) => return err.into_compile_error().into(),
    };
    test_fn.block = Box::new(wrapped_body);

    TokenStream::from(quote! { #test_fn })
}

fn parse_label(args: Punctuated<Meta, Token![,]>) -> syn::Result<Option<LitStr>> {
    let mut label = None;

    for arg in args {
        match arg {
            Meta::NameValue(MetaNameValue { path, value, .. }) if path.is_ident("label") => {
                if label.is_some() {
                    return Err(syn::Error::new_spanned(path, "duplicate `label` argument"));
                }

                match value {
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(label_lit),
                        ..
                    }) => {
                        label = Some(label_lit);
                    }
                    _ => {
                        return Err(syn::Error::new_spanned(
                            value,
                            "`label` must be a string literal, for example: label = \"baseline\"",
                        ));
                    }
                }
            }
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "unsupported argument, expected `label = \"...\"`",
                ));
            }
        }
    }

    Ok(label)
}

#[cfg(test)]
mod lib_tests;
