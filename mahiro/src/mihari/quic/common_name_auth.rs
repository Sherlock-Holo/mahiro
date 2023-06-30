use std::collections::HashSet;

use tracing::instrument;

#[derive(Debug)]
pub struct CommonNameAuthStore {
    common_names: HashSet<String>,
}

impl CommonNameAuthStore {
    pub fn new<N: Into<String>, I: IntoIterator<Item = N>>(common_names: I) -> Self {
        let common_names = common_names
            .into_iter()
            .map(|common_name| common_name.into())
            .collect();

        Self { common_names }
    }

    #[instrument]
    pub fn auth(&self, common_name: &str) -> bool {
        self.common_names.contains(common_name)
    }
}
