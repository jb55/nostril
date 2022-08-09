websocat:
	git clone https://github.com/vi/websocat.git websc || true
	mkdir -p /usr/local/bin
	cd websc && cargo install --path=. && install -v target/release/websocat /usr/local/bin
