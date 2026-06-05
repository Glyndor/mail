fn main() {
	println!("{}", version());
}

/// Human-readable version line, used by `main` and (later) the CLI.
fn version() -> String {
	format!("mail {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn version_includes_package_version() {
		assert_eq!(version(), format!("mail {}", env!("CARGO_PKG_VERSION")));
	}

	#[test]
	fn main_prints_version() {
		main();
	}
}
