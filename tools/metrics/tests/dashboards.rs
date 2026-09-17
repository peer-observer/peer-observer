//! Checks the Grafana dashboards in the `dashboards/` directory.
//!
//! Each dashboard must have a description. The description is stored as a
//! dashboard "link" (shown at the top of the dashboard in Grafana) with the
//! `doc` icon and a `url` of `#`, so clicking it does nothing. The link `title`
//! holds the description text. See
//! https://github.com/peer-observer/peer-observer/issues/421 for background.
//!
//! To list all dashboards with their descriptions, run:
//!
//! ```text
//! cargo test -p metrics --test dashboards -- --nocapture
//! ```

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const DASHBOARDS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dashboards");

/// Recursively collects all `.json` files below `dir`, sorted by path.
fn dashboard_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("could not read {dir:?}: {e}")) {
        let path = entry.expect("could not read directory entry").path();
        if path.is_dir() {
            files.extend(dashboard_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// Returns the description of a dashboard: the title of the first link with
/// the `doc` icon that points to `#`. Returns `None` if there is no such link
/// or the title is empty.
fn description(dashboard: &Value) -> Option<&str> {
    dashboard
        .get("links")?
        .as_array()?
        .iter()
        .find(|link| {
            link.get("type").and_then(Value::as_str) == Some("link")
                && link.get("icon").and_then(Value::as_str) == Some("doc")
                && link.get("url").and_then(Value::as_str) == Some("#")
        })?
        .get("title")?
        .as_str()
        .map(str::trim)
        .filter(|title| !title.is_empty())
}

#[test]
fn dashboards_have_descriptions() {
    let dir = Path::new(DASHBOARDS_DIR);
    let files = dashboard_files(dir);
    assert!(!files.is_empty(), "no dashboards found in {dir:?}");

    let mut missing = Vec::new();
    for file in &files {
        let name = file.strip_prefix(dir).unwrap().display();
        let content =
            fs::read_to_string(file).unwrap_or_else(|e| panic!("could not read {name}: {e}"));
        let dashboard: Value = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("could not parse {name} as JSON: {e}"));

        match description(&dashboard) {
            Some(desc) => println!("{name}\n    {desc}\n"),
            None => {
                println!("{name}\n    <MISSING DESCRIPTION>\n");
                missing.push(name.to_string());
            }
        }
    }

    println!(
        "{} dashboards, {} without description",
        files.len(),
        missing.len()
    );
    assert!(
        missing.is_empty(),
        "dashboards without a description link (see tools/metrics/README.md): {missing:#?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn description_from_doc_link() {
        let dashboard = json!({
            "links": [
                { "type": "dashboards", "icon": "external link", "url": "", "title": "other" },
                { "type": "link", "icon": "doc", "url": "#", "title": "  A description.  " }
            ]
        });
        assert_eq!(description(&dashboard), Some("A description."));
    }

    #[test]
    fn no_description() {
        assert_eq!(description(&json!({})), None);
        assert_eq!(description(&json!({ "links": [] })), None);
        assert_eq!(
            description(
                &json!({ "links": [{ "type": "link", "icon": "doc", "url": "#", "title": " " }] })
            ),
            None
        );
        assert_eq!(
            description(
                &json!({ "links": [{ "type": "link", "icon": "doc", "url": "https://example.com", "title": "x" }] })
            ),
            None
        );
        assert_eq!(
            description(
                &json!({ "links": [{ "type": "link", "icon": "info", "url": "#", "title": "x" }] })
            ),
            None
        );
    }
}
