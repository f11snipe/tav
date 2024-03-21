use std::fs::File;
use std::io::BufReader;
use tav::ConfigData;

fn main() -> Result<(), serde_yaml::Error> {
    let file = File::open("conf/config.yaml").expect("Missing config.yaml file");
    let buf_reader = BufReader::new(file);

    let testing: ConfigData = serde_yaml::from_reader(buf_reader)?;

    dbg!(&testing);

    let fs_watch = &testing.fs.watch.unwrap_or_else(|| Vec::new());
    let fs_blacklist = &testing.fs.blacklist.unwrap_or_else(|| Vec::new());

    let ps_watch = &testing.ps.watch.unwrap_or_else(|| Vec::new());
    let ps_blacklist = &testing.ps.blacklist.unwrap_or_else(|| Vec::new());

    for f in fs_watch {
        println!("FS Watch: {}", f);
    }
    for f in fs_blacklist {
        println!("FS Blacklist: {}", f);
    }

    for p in ps_watch {
        println!("PS Watch: {}", p);
    }
    for p in ps_blacklist {
        println!("PS Blacklist: {}", p);
    }

    for d in fs_watch {
        if let Err(e) = tav::files::walk(d, fs_blacklist) {
            println!("error: {:?}", e);
        }

        // TODO: Need to make async or multi-threaded?
        // if let Err(e) = tav::files::watch(d, fs_blacklist) {
        //     println!("error: {:?}", e);
        // }
    }

    // just watch current directory for now
    if let Err(e) = tav::files::watch(".", fs_blacklist) {
        println!("error: {:?}", e);
    }

    Ok(())
}
