# tav

*Basic terminal anti-virus*

### Features

- Actively monitor filesystem and processes
- Delete blacklisted files automatically
- Monitor processes by regex (no action)
- Blacklist processes globally
- Prohibit processes by user

### Install

```bash
cargo install tav
```

### Examples

```bash
# Run with default config: conf/config.yaml
tav run

# Override config location (path to yaml file)
tav run --config ./config.yaml

# Load and test/debug config file
tav config --config ./config.yaml
```

### Config Example

```yaml
# Filesystem options
fs:
  # List of directories to walk & watch
  watch:
    - /etc
    - /tmp
    - /var/tmp
    - /var/www
  # Blacklist files (simple case insensitive regex)
  blacklist:
    - badfile.*
    - deleteme[0-9]+
    - dontletmelive
# Process options
ps:
  # Watch for processes (no action)
  watch:
    - python
    - sketchy
  # Blacklist processes (partial case insensitive compare)
  blacklist:
    - malwareps
    - killthisproc
  # Blacklist processes for specific users
  prohibit:
    # Don't allow www-data user to run sh or bash processes
    www-data:
      - /bin/sh
      - /bin/bash
```

### Usage

**Default Options**
```bash
# tav --help
A basic terminal anti-virus

Usage: tav [OPTIONS] [COMMAND]

Commands:
  run     Run active scanner and watcher
  config  Config test
  help    Print this message or the help of the given subcommand(s)

Options:
  -B, --no-banner  Don't show the banner
  -v, --verbose    Show additional info logs
  -h, --help       Print help
  -V, --version    Print version
```

**Run Options**
```bash
# tav run --help
Run active scanner and watcher

Usage: tav run [OPTIONS]

Options:
  -c, --config <FILE>  Path to config file (yaml) [default: conf/config.yaml]
  -h, --help           Print help
```

**Config Options**
```bash
# tav config --help
Config test

Usage: tav config [OPTIONS]

Options:
  -c, --config <FILE>  Path to config file (yaml) [default: conf/config.yaml]
  -h, --help           Print help
```
