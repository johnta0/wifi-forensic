//! Utility for running external commands with a timeout.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

/// Result of running an external command.
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    /// Exit code. `None` on timeout or when terminated by a signal.
    pub code: Option<i32>,
    pub timed_out: bool,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Reads a pipe to the end on a separate thread and returns the result over a channel.
///
/// If a descendant process keeps the pipe open, EOF never arrives, so the receiver caps how long it waits.
/// Returns `Err` if the thread cannot be spawned (does not panic).
fn drain<R: Read + Send + 'static>(mut pipe: R) -> anyhow::Result<Receiver<Vec<u8>>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("wfx-drain".into())
        .spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            let _ = tx.send(buf);
        })
        .map_err(|e| anyhow::anyhow!("cannot spawn reader thread: {e}"))?;
    Ok(rx)
}

/// Spawns `program` with `args` and kills it once `timeout` is exceeded.
///
/// Returns `Err` if the process fails to start (e.g. the command does not exist).
/// stdin is closed (so the command cannot hang waiting for input). Both stdout and stderr are captured.
pub fn run(program: &str, args: &[&str], timeout: Duration) -> anyhow::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot start {program}: {e}"))?;

    let readers = (|| -> anyhow::Result<_> {
        let out = drain(child.stdout.take().ok_or_else(|| anyhow::anyhow!("no stdout pipe"))?)?;
        let err = drain(child.stderr.take().ok_or_else(|| anyhow::anyhow!("no stderr pipe"))?)?;
        Ok((out, err))
    })();
    let (out_rx, err_rx) = match readers {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };

    let start = Instant::now();
    let (code, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status.code(), false);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break (None, true);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // On normal exit EOF follows right away. On timeout, give up after 1 second even if a descendant holds the pipe
    let grace = if timed_out { Duration::from_secs(1) } else { Duration::from_secs(5) };
    let stdout = String::from_utf8_lossy(&out_rx.recv_timeout(grace).unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_rx.recv_timeout(Duration::from_millis(500)).unwrap_or_default()).into_owned();
    Ok(Output { stdout, stderr, code, timed_out })
}
