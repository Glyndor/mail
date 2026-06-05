fn main() {
	println!("mail {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
	#[test]
	fn version_is_set() {
		assert!(!env!("CARGO_PKG_VERSION").is_empty());
	}
}
