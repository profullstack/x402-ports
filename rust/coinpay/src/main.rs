//! `coinpay` from cargo: a launcher for the CoinPay CLI, `@profullstack/coinpay` on npm.
//!
//! Order: `$COINPAY_BIN`; a `coinpay` on PATH that is not this launcher; then
//! `npx`, `bunx`, `pnpm dlx` or `deno run`. `$COINPAY_VERSION` pins the npm version.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

const PKG: &str = "@profullstack/coinpay";

fn spec() -> String {
    match env::var("COINPAY_VERSION") {
        Ok(v) if !v.is_empty() => format!("{PKG}@{v}"),
        _ => PKG.to_string(),
    }
}

fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        vec![".exe".into(), ".cmd".into(), ".bat".into(), String::new()]
    } else {
        vec![String::new()]
    };
    for dir in env::split_paths(&path) {
        for ext in &exts {
            let p = dir.join(format!("{name}{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn real_cli() -> Option<PathBuf> {
    let me = env::current_exe().ok().and_then(|p| p.canonicalize().ok());
    let found = which("coinpay")?;
    let canon = found.canonicalize().ok();
    if canon.is_some() && canon == me {
        return None;
    }
    Some(found)
}

pub fn command(args: &[String]) -> Option<Vec<String>> {
    if let Ok(exe) = env::var("COINPAY_BIN") {
        if !exe.is_empty() {
            return Some(std::iter::once(exe).chain(args.iter().cloned()).collect());
        }
    }
    if let Some(real) = real_cli() {
        return Some(
            std::iter::once(real.to_string_lossy().into_owned())
                .chain(args.iter().cloned())
                .collect(),
        );
    }
    let runners: [Vec<String>; 4] = [
        vec!["npx".into(), "--yes".into(), spec()],
        vec!["bunx".into(), spec()],
        vec!["pnpm".into(), "dlx".into(), spec()],
        vec![
            "deno".into(),
            "run".into(),
            "-A".into(),
            format!("npm:{}", spec()),
        ],
    ];
    for r in runners {
        if which(&r[0]).is_some() || Path::new(&r[0]).is_file() {
            return Some(r.into_iter().chain(args.iter().cloned()).collect());
        }
    }
    None
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = command(&args) else {
        eprintln!("coinpay: the CoinPay CLI runs on Node.js 20+ (or Bun or Deno), and none was found.\n  Install Node from https://nodejs.org, then either run this command again\n  or install the CLI directly: npm install -g @profullstack/coinpay");
        exit(127);
    };
    match Command::new(&cmd[0]).args(&cmd[1..]).status() {
        Ok(s) => exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("coinpay: could not run {}: {e}", cmd[0]);
            exit(126);
        }
    }
}
