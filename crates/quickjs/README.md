# Private QuickJS producer

This standalone workspace produces the embedded Wasm for [javascript](../javascript/README.md).
It provides no public native execution API. Artifact maintainers build it through
`just quickjs-wasm-build` at the root of the full development checkout. The public source
distribution includes the generated guest and does not include the maintenance scripts or Just recipes.
The native workspace excludes this package so host applications cannot link QuickJS through workspace feature unification.
