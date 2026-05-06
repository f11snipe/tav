pub struct CmdExit {
    pub code: exitcode::ExitCode,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_foo() {
        assert_ne!(4, 5);
    }
}
