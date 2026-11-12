//! The command line: `bxplore --dump`.

use std::process::{Command, Stdio};

/// `bxplore --dump file | head` closes the pipe early; that is not an error.
#[test]
fn dump_into_a_closed_pipe_is_not_an_error() {
    // This test executable is large enough that its dump cannot fit in a pipe buffer.
    let big = std::env::current_exe().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_bxplore")).arg("--dump").arg(&big).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "status {:?}, stderr: {}", out.status, String::from_utf8_lossy(&out.stderr));
    assert!(out.stderr.is_empty(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn dump_prints_the_description_first() {
    let out = Command::new(env!("CARGO_BIN_EXE_bxplore")).arg("--dump").arg(std::env::current_exe().unwrap()).output().unwrap();
    assert!(out.status.success());
    let first = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or_default().to_string();
    assert!(first.contains(": ") && (first.contains("Mach-O") || first.contains("ELF") || first.contains("PE")), "{first}");
}

#[test]
fn dump_of_a_missing_file_fails() {
    let out = Command::new(env!("CARGO_BIN_EXE_bxplore")).args(["--dump", "/no/such/file"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stderr.is_empty());
}
