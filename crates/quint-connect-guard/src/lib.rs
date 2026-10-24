//! Test-only wrapper that binds a Quint connector to compiled metadata.

#![deny(unsafe_code)]

mod constants;

use constants::{FIELD_SEPARATOR, MARKER_PREFIX};
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Expr, ExprLit, ItemFn, Lit, Meta, Token, parse::Parser, punctuated::Punctuated,
    spanned::Spanned,
};

#[derive(Default)]
struct Metadata {
    spec: Option<String>,
    main: Option<String>,
    init: Option<String>,
    step: Option<String>,
    max_samples: Option<String>,
    max_steps: Option<String>,
}

impl Metadata {
    fn read(meta: &Meta, name: &str) -> syn::Result<Option<String>> {
        if !meta.path().is_ident(name) {
            return Ok(None);
        }
        let Meta::NameValue(value) = meta else {
            return Err(syn::Error::new(
                meta.span(),
                "expected a name-value attribute",
            ));
        };
        let Expr::Lit(ExprLit { lit, .. }) = &value.value else {
            return Err(syn::Error::new(
                value.value.span(),
                "expected a literal attribute value",
            ));
        };
        let value = match lit {
            Lit::Str(value) => value.value(),
            Lit::Int(value) => value.to_string(),
            _ => {
                return Err(syn::Error::new(
                    lit.span(),
                    "expected a string or integer literal",
                ));
            }
        };
        Ok(Some(value))
    }

    fn parse(args: TokenStream) -> syn::Result<(Self, Punctuated<Meta, Token![,]>)> {
        let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
        let parsed_args = parser.parse(args)?;
        let mut metadata = Self::default();
        let mut upstream_args = Punctuated::new();
        for meta in parsed_args {
            if meta.path().is_ident("guard_path") || meta.path().is_ident("marker") {
                return Err(syn::Error::new(
                    meta.span(),
                    "connector provenance arguments are compiler-derived; remove this argument",
                ));
            } else if let Some(value) = Self::read(&meta, "spec")? {
                metadata.spec = Some(value);
                upstream_args.push(meta);
            } else if let Some(value) = Self::read(&meta, "main")? {
                metadata.main = Some(value);
                upstream_args.push(meta);
            } else if let Some(value) = Self::read(&meta, "init")? {
                metadata.init = Some(value);
                upstream_args.push(meta);
            } else if let Some(value) = Self::read(&meta, "step")? {
                metadata.step = Some(value);
                upstream_args.push(meta);
            } else if let Some(value) = Self::read(&meta, "max_samples")? {
                metadata.max_samples = Some(value);
                upstream_args.push(meta);
            } else if let Some(value) = Self::read(&meta, "max_steps")? {
                metadata.max_steps = Some(value);
                upstream_args.push(meta);
            } else {
                upstream_args.push(meta);
            }
        }
        Ok((metadata, upstream_args))
    }

    fn marker_record(self, source_path: &str, function_name: &str) -> String {
        [
            Some(source_path.to_owned()),
            Some(function_name.to_owned()),
            self.spec,
            self.main,
            self.init,
            self.step,
            self.max_samples,
            self.max_steps,
        ]
        .into_iter()
        .map(|value| value.unwrap_or_default())
        .collect::<Vec<_>>()
        .join(&FIELD_SEPARATOR.to_string())
    }
}

fn source_path(test_fn: &ItemFn) -> syn::Result<String> {
    test_fn
        .sig
        .ident
        .span()
        .local_file()
        .or_else(|| test_fn.span().local_file())
        .and_then(|path| path.to_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            syn::Error::new(
                test_fn.sig.ident.span(),
                "cannot derive connector source identity from compiler span",
            )
        })
}

fn encode_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn compile_error(error: syn::Error) -> TokenStream {
    error.to_compile_error().into()
}

#[proc_macro_attribute]
pub fn quint_run(args: TokenStream, item: TokenStream) -> TokenStream {
    let (metadata, args) = match Metadata::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => return compile_error(error),
    };

    let test_fn = match syn::parse::<ItemFn>(item) {
        Ok(test_fn) => test_fn,
        Err(error) => return compile_error(error),
    };
    if let Some(attribute) = test_fn.attrs.iter().find(|attribute| {
        attribute.path().is_ident("ignore")
            || attribute.path().is_ident("should_panic")
            || attribute.path().is_ident("test")
    }) {
        return compile_error(syn::Error::new(
            attribute.span(),
            "connector functions cannot carry test-semantic attributes",
        ));
    }
    let source_path = match source_path(&test_fn) {
        Ok(path) => path,
        Err(error) => return compile_error(error),
    };
    let function_name = test_fn.sig.ident.to_string();
    let marker_suffix = encode_hex(&metadata.marker_record(&source_path, &function_name));
    let marker = format!("{MARKER_PREFIX}{marker_suffix}");
    let marker_ident = syn::Ident::new(&marker, proc_macro2::Span::call_site());
    let cfg_attributes = test_fn
        .attrs
        .iter()
        .filter(|attribute| {
            attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr")
        })
        .collect::<Vec<_>>();

    quote! {
        #[::quint_connect::quint_run(#args)]
        #test_fn

      #(#cfg_attributes)*
      #[doc(hidden)]
      #[test]
      fn #marker_ident() {}
    }
    .into()
}
