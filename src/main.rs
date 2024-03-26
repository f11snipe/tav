use tav::run;

fn main() -> Result<(), serde_yaml::Error> {
    run("conf/config.yaml")?;

    Ok(())
}
