#![doc(hidden)]

use proc_macro::TokenStream;

mod count_allocations;

#[proc_macro_attribute]
pub fn count_allocations(args: TokenStream, input: TokenStream) -> TokenStream {
    count_allocations::expand(args, input)
}

#[cfg(test)]
mod count_allocations_tests;
