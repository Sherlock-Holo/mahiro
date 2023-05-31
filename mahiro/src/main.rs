fn main() -> anyhow::Result<()> {
    ring_io::block_on(mahiro::run())
}
