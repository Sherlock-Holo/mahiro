#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    cola::run().await
}
