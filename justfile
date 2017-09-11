secret = 'target/pass.secret'
config = 'target/config.toml'
lock = 'target/novault.lock'

# run with the given flags
run CMD="":
	@mkdir -p target
	@echo "shakeitoff" > {{secret}}
	cargo build --release
	cat {{secret}} | target/release/novault \
		--stdin --stdout --config {{config}} --lock {{lock}} \
		{{CMD}}
	@echo "-------- CONFIG --------"
	@cat {{config}}
	@echo "------------------------"
