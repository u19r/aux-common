use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use syn::{
    Attribute, Expr, ExprLit, Item, ItemFn, ItemMod, Lit, Meta, ReturnType, Token, Type,
    TypeParamBound, UseTree, parse::Parser, punctuated::Punctuated,
};

use super::{ActiveConfiguration, invalid};

pub(super) fn run(
    source_root: PathBuf,
    lib_path: PathBuf,
    display_root: PathBuf,
    configuration: ActiveConfiguration,
) -> Result<(), Box<dyn Error>> {
    let mut inventory = SourceInventory {
        source_root,
        display_root,
        configuration,
        visited: BTreeSet::new(),
    };
    let source_directory = lib_path
        .parent()
        .ok_or_else(|| invalid("library source has no parent directory"))?;
    inventory
        .visit_file(&lib_path, source_directory)
        .map(|_| ())
}

struct SourceInventory {
    source_root: PathBuf,
    display_root: PathBuf,
    configuration: ActiveConfiguration,
    visited: BTreeSet<PathBuf>,
}

impl SourceInventory {
    fn visit_file(&mut self, path: &Path, module_directory: &Path) -> Result<bool, Box<dyn Error>> {
        let path = canonicalize(path, "Rust source")?;
        if !path.starts_with(&self.source_root) {
            return Err(invalid(format!(
                "Rust source is outside the source snapshot: {}",
                path.display()
            )));
        }
        if !self.visited.insert(path.clone()) {
            return Ok(false);
        }
        let source = fs::read_to_string(&path)?;
        let file = syn::parse_file(&source)?;
        let (active, attributes) = active_attributes(&file.attrs, &self.configuration)?;
        if !active {
            return Ok(false);
        }
        reject_procedural_attributes(&attributes, "source file")?;
        self.visit_items(&path, &file.items, module_directory, false)
    }

    fn visit_items(
        &mut self,
        path: &Path,
        items: &[Item],
        module_directory: &Path,
        ancestor_has_glob: bool,
    ) -> Result<bool, Box<dyn Error>> {
        let local_has_glob = items.iter().try_fold(false, |has_glob, item| {
            let (active, _) = active_attributes(item_attrs(item), &self.configuration)?;
            Ok::<_, Box<dyn Error>>(
                has_glob
                    || (active
                        && matches!(item, Item::Use(import) if glob_import_can_shadow(&import.tree))),
            )
        })?;
        let connector_scope_has_glob = ancestor_has_glob || local_has_glob;
        let mut contains_guarded_connector = false;
        let mut has_dynamic_item_macro = false;
        let mut has_procedural_item_attribute = false;
        for item in items {
            let (active, attributes) = active_attributes(item_attrs(item), &self.configuration)?;
            if !active {
                continue;
            }
            has_procedural_item_attribute |= attributes.iter().any(|attribute| {
                !is_builtin_attribute(attribute) && !is_guard_attribute(attribute)
            });
            match item {
                Item::Macro(item_macro) if item_macro.ident.is_none() => {
                    has_dynamic_item_macro = true;
                }
                Item::ExternCrate(extern_crate)
                    if extern_crate
                        .rename
                        .as_ref()
                        .is_some_and(|rename| rename.1 == "quint_connect_guard") =>
                {
                    return Err(invalid(
                        "active extern crate alias shadows quint_connect_guard",
                    ));
                }
                Item::ExternCrate(extern_crate)
                    if extern_crate
                        .rename
                        .as_ref()
                        .is_some_and(|rename| rename.1 == "quint_connect") =>
                {
                    return Err(invalid("active extern crate alias shadows quint_connect"));
                }
                Item::Use(import) if binds_guard_name(&import.tree) => {
                    return Err(invalid("active use alias shadows quint_connect_guard"));
                }
                Item::Use(import) if binds_connect_name(&import.tree) => {
                    return Err(invalid("active use alias shadows quint_connect"));
                }
                Item::Mod(module) if module.ident == "quint_connect_guard" => {
                    return Err(invalid("active module shadows quint_connect_guard"));
                }
                Item::Mod(module) if module.ident == "quint_connect" => {
                    return Err(invalid("active module shadows quint_connect"));
                }
                Item::Fn(function) => {
                    contains_guarded_connector |=
                        self.visit_function(path, function, &attributes, connector_scope_has_glob)?
                }
                Item::Mod(module) => {
                    contains_guarded_connector |= self.visit_module(
                        path,
                        module,
                        &attributes,
                        module_directory,
                        connector_scope_has_glob,
                    )?
                }
                _ => {}
            }
        }
        if contains_guarded_connector && has_dynamic_item_macro {
            return Err(invalid(
                "active item macro in connector ancestry is not accepted by the provenance guard",
            ));
        }
        if contains_guarded_connector && has_procedural_item_attribute {
            return Err(invalid(
                "procedural attribute in connector scope is not accepted by the provenance guard",
            ));
        }
        Ok(contains_guarded_connector)
    }

    fn visit_module(
        &mut self,
        path: &Path,
        module: &ItemMod,
        attributes: &[Meta],
        module_directory: &Path,
        ancestor_has_glob: bool,
    ) -> Result<bool, Box<dyn Error>> {
        reject_procedural_attributes(attributes, "module ancestor")?;
        if let Some((_, items)) = &module.content {
            return self.visit_items(
                path,
                items,
                &module_directory.join(module.ident.to_string()),
                ancestor_has_glob,
            );
        }
        let child = resolve_module_path(
            &module.ident,
            attributes,
            path.parent()
                .ok_or_else(|| invalid("Rust source has no parent directory"))?,
            module_directory,
            &self.source_root,
        )?;
        self.visit_file(&child.path, &child.directory)
    }

    fn visit_function(
        &self,
        path: &Path,
        function: &ItemFn,
        attributes: &[Meta],
        scope_has_glob: bool,
    ) -> Result<bool, Box<dyn Error>> {
        let guard_count = attributes
            .iter()
            .filter(|attribute| is_guard_attribute(attribute))
            .count();
        if guard_count == 0 {
            if attributes.iter().any(is_guard_name) {
                return Err(invalid(
                    "connector guard attribute must use absolute ::quint_connect_guard::quint_run",
                ));
            }
            return Ok(false);
        }
        if guard_count > 1 {
            return Err(invalid("connector has multiple guard attributes"));
        }
        if scope_has_glob {
            return Err(invalid("active glob import can shadow quint_connect_guard"));
        }
        if attributes.iter().any(is_test_semantic_attribute) {
            return Err(invalid(
                "connector functions cannot carry ignore, should_panic, or test attributes",
            ));
        }

        for attribute in attributes {
            if is_guard_attribute(attribute) {
                let values = parse_guard_attribute(attribute)?;
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    self.display_path(path).display(),
                    function.sig.ident,
                    values.spec,
                    values.main,
                    values.init,
                    values.step,
                    values.max_samples,
                    values.max_steps,
                    if returns_driver(function) { 1 } else { 0 }
                );
                continue;
            }
            if is_guard_name(attribute) {
                return Err(invalid(
                    "connector guard attribute must use absolute ::quint_connect_guard::quint_run",
                ));
            }
            if !is_builtin_attribute(attribute) {
                return Err(invalid(
                    "trusted quint_connect_guard attribute cannot be combined with another \
                     procedural attribute",
                ));
            }
        }
        Ok(true)
    }

    fn display_path(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.source_root)
            .map(|relative| self.display_root.join(relative))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn reject_procedural_attributes(attributes: &[Meta], owner: &str) -> Result<(), Box<dyn Error>> {
    if attributes
        .iter()
        .any(|attribute| !is_builtin_attribute(attribute))
    {
        return Err(invalid(format!(
            "procedural attribute on {owner} can shadow quint_connect_guard"
        )));
    }
    Ok(())
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn binds_guard_name(tree: &UseTree) -> bool {
    binds_name(tree, "quint_connect_guard")
}

fn binds_connect_name(tree: &UseTree) -> bool {
    binds_name(tree, "quint_connect")
}

fn binds_name(tree: &UseTree, protected_name: &str) -> bool {
    match tree {
        UseTree::Name(name) => name.ident == protected_name,
        UseTree::Rename(rename) => rename.rename == protected_name,
        UseTree::Path(path) => binds_name(&path.tree, protected_name),
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| binds_name(item, protected_name)),
        UseTree::Glob(_) => false,
    }
}

fn is_test_semantic_attribute(attribute: &Meta) -> bool {
    attribute.path().is_ident("ignore")
        || attribute.path().is_ident("should_panic")
        || attribute.path().is_ident("test")
}

fn glob_import_can_shadow(tree: &UseTree) -> bool {
    match tree {
        UseTree::Path(path) => glob_import_can_shadow(&path.tree),
        UseTree::Group(group) => group.items.iter().any(glob_import_can_shadow),
        UseTree::Glob(_) => true,
        UseTree::Name(_) | UseTree::Rename(_) => false,
    }
}

struct ResolvedModule {
    path: PathBuf,
    directory: PathBuf,
}

fn resolve_module_path(
    name: &syn::Ident,
    attributes: &[Meta],
    source_directory: &Path,
    module_directory: &Path,
    workspace_root: &Path,
) -> Result<ResolvedModule, Box<dyn Error>> {
    let mut explicit_path = None;
    for attribute in attributes {
        if !attribute.path().is_ident("path") {
            continue;
        }
        if explicit_path.is_some() {
            return Err(invalid(format!(
                "module {name} has multiple path attributes"
            )));
        }
        let Meta::NameValue(value) = attribute else {
            return Err(invalid("module path attribute must be a string literal"));
        };
        let Expr::Lit(ExprLit {
            lit: Lit::Str(value),
            ..
        }) = &value.value
        else {
            return Err(invalid("module path attribute must be a string literal"));
        };
        explicit_path = Some(value.value());
    }

    let candidates = if let Some(path) = &explicit_path {
        vec![source_directory.join(path)]
    } else {
        vec![
            module_directory.join(format!("{name}.rs")),
            module_directory.join(name.to_string()).join("mod.rs"),
        ]
    };
    let existing = candidates
        .into_iter()
        .filter(|candidate| candidate.is_file())
        .collect::<Vec<_>>();
    if existing.len() != 1 {
        return Err(invalid(format!(
            "active module {name} must resolve to exactly one source file"
        )));
    }
    let resolved = canonicalize(&existing[0], "module source")?;
    if !resolved.starts_with(workspace_root) {
        return Err(invalid(format!(
            "module source is outside the package: {}",
            resolved.display()
        )));
    }
    let directory = explicit_path
        .is_some()
        .then(|| {
            resolved
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| invalid("explicit module source has no parent directory"))
        })
        .transpose()?
        .unwrap_or_else(|| module_directory.join(name.to_string()));
    Ok(ResolvedModule {
        path: resolved,
        directory,
    })
}

fn active_attributes(
    attributes: &[Attribute],
    configuration: &ActiveConfiguration,
) -> Result<(bool, Vec<Meta>), Box<dyn Error>> {
    let mut active = true;
    let mut effective = Vec::new();
    for attribute in attributes {
        apply_attribute(&attribute.meta, configuration, &mut active, &mut effective)?;
    }
    Ok((active, effective))
}

fn apply_attribute(
    attribute: &Meta,
    configuration: &ActiveConfiguration,
    active: &mut bool,
    effective: &mut Vec<Meta>,
) -> Result<(), Box<dyn Error>> {
    if attribute.path().is_ident("cfg") {
        let predicate = cfg_attribute_predicate(attribute)?;
        *active &= predicate_matches(&predicate, configuration)?;
        return Ok(());
    }
    if attribute.path().is_ident("cfg_attr") {
        let (condition, emitted) = cfg_attr_parts(attribute)?;
        if predicate_matches(&condition, configuration)? {
            for attribute in &emitted {
                apply_attribute(attribute, configuration, active, effective)?;
            }
        }
        return Ok(());
    }
    effective.push(attribute.clone());
    Ok(())
}

fn cfg_attribute_predicate(attribute: &Meta) -> Result<Meta, Box<dyn Error>> {
    let Meta::List(list) = attribute else {
        return Err(invalid("cfg attribute must have one predicate"));
    };
    let predicates = parse_metas(&list.tokens)?;
    if predicates.len() != 1 {
        return Err(invalid("cfg attribute must have one predicate"));
    }
    predicates
        .into_iter()
        .next()
        .ok_or_else(|| invalid("cfg attribute must have one predicate"))
}

fn cfg_attr_parts(attribute: &Meta) -> Result<(Meta, Vec<Meta>), Box<dyn Error>> {
    let Meta::List(list) = attribute else {
        return Err(invalid("cfg_attr must have a condition"));
    };
    let mut attributes = parse_metas(&list.tokens)?;
    if attributes.is_empty() {
        return Err(invalid("cfg_attr must have a condition"));
    }
    let condition = attributes.remove(0);
    Ok((condition, attributes))
}

fn predicate_matches(
    predicate: &Meta,
    configuration: &ActiveConfiguration,
) -> Result<bool, Box<dyn Error>> {
    match predicate {
        Meta::Path(path) => Ok(path
            .get_ident()
            .is_some_and(|name| configuration.matches(&name.to_string(), None))),
        Meta::NameValue(value) => {
            let Some(name) = value.path.get_ident() else {
                return Err(invalid("cfg name must be an identifier"));
            };
            let Expr::Lit(ExprLit {
                lit: Lit::Str(value),
                ..
            }) = &value.value
            else {
                return Err(invalid("cfg value must be a string literal"));
            };
            Ok(configuration.matches(&name.to_string(), Some(&value.value())))
        }
        Meta::List(list) => {
            let predicates = parse_metas(&list.tokens)?;
            if list.path.is_ident("all") {
                for predicate in &predicates {
                    if !predicate_matches(predicate, configuration)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            } else if list.path.is_ident("any") {
                for predicate in &predicates {
                    if predicate_matches(predicate, configuration)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            } else if list.path.is_ident("not") {
                if predicates.len() != 1 {
                    return Err(invalid("cfg not must have one predicate"));
                }
                Ok(!predicate_matches(&predicates[0], configuration)?)
            } else {
                Err(invalid("unsupported cfg predicate"))
            }
        }
    }
}

#[derive(Default)]
struct GuardValues {
    spec: String,
    main: String,
    init: String,
    step: String,
    max_samples: String,
    max_steps: String,
}

fn is_guard_attribute(attribute: &Meta) -> bool {
    let segments = attribute.path().segments.iter().collect::<Vec<_>>();
    attribute.path().leading_colon.is_some()
        && segments.len() == 2
        && segments[0].ident == "quint_connect_guard"
        && segments[1].ident == "quint_run"
}

fn is_guard_name(attribute: &Meta) -> bool {
    let segments = attribute.path().segments.iter().collect::<Vec<_>>();
    segments.len() == 2
        && segments[0].ident == "quint_connect_guard"
        && segments[1].ident == "quint_run"
}

fn is_builtin_attribute(attribute: &Meta) -> bool {
    let Some(name) = attribute.path().get_ident().map(ToString::to_string) else {
        return false;
    };
    matches!(
        name.as_str(),
        "allow"
            | "automatically_derived"
            | "cfg"
            | "cfg_attr"
            | "cold"
            | "deny"
            | "deprecated"
            | "doc"
            | "expect"
            | "export_name"
            | "ignore"
            | "inline"
            | "link_name"
            | "must_use"
            | "no_mangle"
            | "non_exhaustive"
            | "path"
            | "repr"
            | "should_panic"
            | "test"
            | "track_caller"
            | "warn"
    )
}

fn parse_guard_attribute(attribute: &Meta) -> Result<GuardValues, Box<dyn Error>> {
    let Meta::List(list) = attribute else {
        return Err(invalid("guard attribute must have a list"));
    };
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let arguments = parser.parse2(list.tokens.clone())?;
    let mut values = GuardValues::default();
    for argument in arguments {
        let Some(name) = argument.path().get_ident().map(ToString::to_string) else {
            continue;
        };
        let value = match argument {
            Meta::NameValue(value) => parse_literal(&value.value)?,
            _ => continue,
        };
        match name.as_str() {
            "spec" => values.spec = value,
            "main" => values.main = value,
            "init" => values.init = value,
            "step" => values.step = value,
            "max_samples" => values.max_samples = value,
            "max_steps" => values.max_steps = value,
            _ => {}
        }
    }
    Ok(values)
}

fn parse_literal(expression: &Expr) -> Result<String, Box<dyn Error>> {
    let Expr::Lit(ExprLit { lit, .. }) = expression else {
        return Err(invalid("guard attribute values must be literals"));
    };
    match lit {
        Lit::Str(value) => Ok(value.value()),
        Lit::Int(value) => Ok(value.to_string()),
        _ => Err(invalid(
            "guard attribute values must be strings or integers",
        )),
    }
}

fn parse_metas(tokens: &proc_macro2::TokenStream) -> Result<Vec<Meta>, Box<dyn Error>> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(tokens.clone())
        .map(|metas| metas.into_iter().collect())
        .map_err(Into::into)
}

fn returns_driver(function: &ItemFn) -> bool {
    let ReturnType::Type(_, return_type) = &function.sig.output else {
        return false;
    };
    let Type::ImplTrait(impl_trait) = return_type.as_ref() else {
        return false;
    };
    impl_trait.bounds.iter().any(|bound| {
        let TypeParamBound::Trait(trait_bound) = bound else {
            return false;
        };
        let segments = &trait_bound.path.segments;
        segments.len() == 1 && segments[0].ident == "Driver"
            || segments.len() == 2
                && segments[0].ident == "quint_connect"
                && segments[1].ident == "Driver"
    })
}

fn canonicalize(path: &Path, description: &str) -> Result<PathBuf, Box<dyn Error>> {
    fs::canonicalize(path).map_err(|error| {
        invalid(format!(
            "cannot resolve {description} {}: {error}",
            path.display()
        ))
    })
}
