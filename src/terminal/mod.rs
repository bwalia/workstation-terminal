//! Pseudo-terminal processes: local shells and the OpenSSH client both run inside a PTY.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::sync::{mpsc, watch};

use crate::config::{Account, Config};

pub const MIN_COLS: u16 = 2;
pub const MAX_COLS: u16 = 1000;
pub const MIN_ROWS: u16 = 1;
pub const MAX_ROWS: u16 = 500;
const READ_CHUNK: usize = 16 * 1024;
/// Starts shells as `local.run_as` (see packaging/sshweb.sudoers).
pub const SUDO: &str = "/usr/bin/sudo";
/// Runs shells inside `local.sandbox_profile` (macOS).
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// What to run inside the PTY. Arguments are passed as a vector; nothing goes through a shell.
#[derive(Debug, Clone)]
pub struct PtySpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// Full environment (the child does not inherit the gateway's environment).
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub cols: u16,
    pub rows: u16,
    /// Run the program as this account through sudo (`local.run_as`); None: as the gateway.
    pub run_as: Option<String>,
    /// Run the program inside this sandbox (`local.sandbox_profile`); None: unsandboxed.
    pub sandbox: Option<Sandbox>,
}

/// A sandbox-exec profile and the parameters it gets (`-D KEY=value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    pub profile: PathBuf,
    pub params: Vec<(String, String)>,
}

/// The account local shells run as and the sandbox they run in, from the config.
fn shell_context(cfg: &Config) -> Result<(Option<Account>, Option<Sandbox>), String> {
    let account = match &cfg.local.run_as {
        Some(u) => Some(
            crate::config::lookup_account(u)
                .ok_or_else(|| format!("local.run_as account {u} does not exist"))?,
        ),
        None => None,
    };
    let sandbox = cfg.local.sandbox_profile.as_ref().map(|profile| {
        let home = match &account {
            Some(a) => a.home.clone(),
            None => crate::config::home_dir(),
        };
        Sandbox {
            profile: profile.clone(),
            params: vec![
                ("HOME".into(), home.to_string_lossy().into_owned()),
                ("OTLP_PORT".into(), cfg.opsapi.work_log.otlp_port.to_string()),
            ],
        }
    });
    Ok((account, sandbox))
}

/// What actually starts for `spec`: its program inside its sandbox, as its account. Each step
/// (sudo, sandbox-exec) replaces itself with the next, so the pid is the program's.
pub fn command_line(spec: &PtySpec) -> (PathBuf, Vec<OsString>) {
    let mut program = spec.program.clone();
    let mut args = spec.args.clone();
    if let Some(sb) = &spec.sandbox {
        let mut a: Vec<OsString> = vec!["-f".into(), sb.profile.clone().into()];
        for (k, v) in &sb.params {
            a.push("-D".into());
            a.push(format!("{k}={v}").into());
        }
        a.push(program.into());
        a.extend(args);
        program = SANDBOX_EXEC.into();
        args = a;
    }
    if let Some(user) = &spec.run_as {
        args = sudo_args(user, &program, &args);
        program = SUDO.into();
    }
    (program, args)
}

pub fn clamp_size(cols: u16, rows: u16) -> (u16, u16) {
    (
        cols.clamp(MIN_COLS, MAX_COLS),
        rows.clamp(MIN_ROWS, MAX_ROWS),
    )
}

/// Environment passed to child processes: a small allowlist plus terminal settings.
pub fn base_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    for k in [
        "HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
    ] {
        if let Ok(v) = std::env::var(k) {
            env.push((k.to_string(), v));
        }
    }
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push(("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()));
    }
    if !env.iter().any(|(k, _)| k == "LANG") {
        env.push(("LANG".into(), "en_US.UTF-8".into()));
    }
    env.push(("TERM".into(), "xterm-256color".into()));
    env.push(("COLORTERM".into(), "truecolor".into()));
    env.push(("TERM_PROGRAM".into(), "sshweb".into()));
    env
}

/// Whose a local tab's shell is: `SSHWEB_USER` (the terminal user) and, from their OpsAPI key when
/// it says, `SSHWEB_USER_EMAIL` and `SSHWEB_USER_NAME`. Everyone's shells may run as one macOS
/// account (`local.run_as`); these let its start-up files credit the person, e.g. in git commits.
/// sudo keeps them (`SSHWEB_*` in packaging/sshweb.sudoers).
pub fn identity_env(
    user: &str,
    key: Option<&crate::auth::keys::AuthorizedKey>,
) -> Vec<(String, String)> {
    let mut env = vec![("SSHWEB_USER".to_string(), user.to_string())];
    let key = key.filter(|k| k.user == user);
    if let Some(email) = key.and_then(|k| k.email.clone()) {
        env.push(("SSHWEB_USER_EMAIL".into(), email));
    }
    if let Some(name) = key.and_then(|k| k.name.clone()) {
        env.push(("SSHWEB_USER_NAME".into(), name));
    }
    env
}

/// Build the spec for a local interactive shell.
pub fn local_shell_spec(
    cfg: &Config,
    shell: Option<&std::path::Path>,
    cols: u16,
    rows: u16,
) -> Result<PtySpec, String> {
    let shell = match shell {
        Some(s) => {
            if !cfg.shell_allowed(s) {
                return Err(format!("shell {} is not permitted", s.display()));
            }
            s.to_path_buf()
        }
        None => cfg.effective_default_shell(),
    };
    if !shell.is_file() {
        return Err(format!("shell {} not found", shell.display()));
    }
    let mut args = Vec::new();
    if cfg.local.login_shell {
        args.push(OsString::from("-l"));
    }
    let (account, sandbox) = shell_context(cfg)?;
    let cwd = cfg.local.working_dir.clone().unwrap_or_else(|| match &account {
        Some(a) => a.home.clone(),
        None => crate::config::home_dir(),
    });
    let mut env = base_env();
    if let Some(a) = &account {
        // The shell's own identity, not the gateway's (sudo sets the same; TMPDIR was the gateway's).
        env.retain(|(k, _)| !matches!(k.as_str(), "HOME" | "USER" | "LOGNAME" | "TMPDIR"));
        env.push(("HOME".into(), a.home.to_string_lossy().into_owned()));
        env.push(("USER".into(), a.name.clone()));
        env.push(("LOGNAME".into(), a.name.clone()));
    }
    env.push(("SHELL".into(), shell.to_string_lossy().into_owned()));
    let (cols, rows) = clamp_size(cols, rows);
    Ok(PtySpec {
        program: shell,
        args,
        env,
        cwd,
        cols,
        rows,
        run_as: account.map(|a| a.name),
        sandbox,
    })
}

/// Check that local shells start inside `local.sandbox_profile`: the profile loads, and the
/// shell is still the process the gateway holds (so it can be stopped).
pub fn check_sandbox(cfg: &Config) -> Result<(), String> {
    let (account, sandbox) = shell_context(cfg)?;
    let spec = PtySpec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "echo \"$$\"".into()],
        env: base_env(),
        cwd: std::env::temp_dir(),
        cols: 80,
        rows: 24,
        run_as: account.map(|a| a.name),
        sandbox,
    };
    let (program, args) = command_line(&spec);
    let child = std::process::Command::new(&program)
        .args(&args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", program.display()))?;
    let pid = child.id().to_string();
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(format!("a test shell didn't start in the sandbox: {}", why.trim()));
    }
    if String::from_utf8_lossy(&out.stdout).trim() != pid {
        return Err("sandbox-exec didn't hand over to the shell".into());
    }
    Ok(())
}

/// `sudo` arguments that run `program args` as `user`. sudo's environment rules (sudoers env_keep)
/// pass the terminal's variables; nothing secret goes on the command line.
pub fn sudo_args(user: &str, program: &std::path::Path, args: &[OsString]) -> Vec<OsString> {
    let mut v: Vec<OsString> = ["-n", "-H", "-u", user, "--"].map(OsString::from).into();
    v.push(program.as_os_str().to_owned());
    v.extend(args.iter().cloned());
    v
}

/// Check that sudo lets this process start shells as `a` the way terminals need: no password, sudo
/// replaced by the program (no root process in between, so the gateway can stop it), HOME set to
/// the account's, and the terminal's variables kept.
pub fn check_run_as(a: &Account) -> Result<(), String> {
    let script = r#"printf '%s\n' "$$" "$(id -un)" "$HOME" "$OPSAPI_P$SSHWEB_P$OTEL_P$CLAUDE_CODE_P""#;
    let args = sudo_args(&a.name, std::path::Path::new("/bin/sh"), &["-c".into(), script.into()]);
    let child = std::process::Command::new(SUDO)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs([("OPSAPI_P", "1"), ("SSHWEB_P", "2"), ("OTEL_P", "3"), ("CLAUDE_CODE_P", "4")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {SUDO}: {e}"))?;
    let pid = child.id().to_string();
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let rule = "install the rule from packaging/sshweb.sudoers";
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(format!("sudo won't start shells as {}: {} ({rule})", a.name, why.trim()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let got: Vec<&str> = text.lines().collect();
    let home = a.home.to_string_lossy();
    if got.first() != Some(&pid.as_str()) {
        return Err(format!(
            "sudo stays running between the gateway and the shell, so it couldn't stop shells: \
             the sudoers Defaults must include !pam_session, !pam_setcred and !use_pty ({rule})"
        ));
    }
    if got.get(1) != Some(&a.name.as_str()) {
        return Err(format!("sudo started the shell as {:?}, not {}", got.get(1), a.name));
    }
    if got.get(2) != Some(&home.as_ref()) {
        return Err(format!("shells get HOME {:?}, not {home}: add always_set_home ({rule})", got.get(2)));
    }
    if got.get(3) != Some(&"1234") {
        return Err(format!(
            "sudo drops the terminal's variables: env_keep must list OPSAPI_* SSHWEB_* OTEL_* CLAUDE_CODE_* ({rule})"
        ));
    }
    Ok(())
}

/// A shell for an OpsAPI task: started in `cwd` with `extra_env`. With an agent command line
/// (from the gateway's config, never from a link), the shell runs it first and then becomes an
/// ordinary interactive shell in the same folder. `-i` makes the user's rc files set PATH etc.
/// exactly as in a normal terminal; the task text is only reachable through `extra_env`.
pub fn task_shell_spec(
    cfg: &Config,
    cwd: std::path::PathBuf,
    extra_env: Vec<(String, String)>,
    run: Option<&str>,
    cols: u16,
    rows: u16,
) -> Result<PtySpec, String> {
    let mut spec = local_shell_spec(cfg, None, cols, rows)?;
    spec.cwd = cwd;
    spec.env.extend(extra_env);
    if let Some(run) = run {
        let shell = spec.program.to_string_lossy().into_owned();
        let login = if cfg.local.login_shell { " -l" } else { "" };
        // Newline, not `;`, so a `# comment` in the run line can't swallow the exec.
        spec.args.push(OsString::from("-i"));
        spec.args.push(OsString::from("-c"));
        spec.args
            .push(OsString::from(format!("{run}\nexec '{shell}'{login}")));
    }
    Ok(spec)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub code: Option<u32>,
}

/// A running process attached to a PTY.
pub struct PtyProcess {
    master: Mutex<Box<dyn MasterPty + Send>>,
    input_tx: mpsc::Sender<Bytes>,
    pid: Option<i32>,
    run_as: Option<String>,
    exit_rx: watch::Receiver<Option<ExitInfo>>,
}

impl PtyProcess {
    /// Spawn the process. Returns the handle and the output stream (closed at EOF).
    pub fn spawn(spec: &PtySpec) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows: spec.rows,
                cols: spec.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("openpty failed")?;
        let (program, args) = command_line(spec);
        let mut cmd = CommandBuilder::new(&program);
        cmd.args(&args);
        cmd.env_clear();
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        cmd.cwd(&spec.cwd);
        let mut child = pair
            .slave
            .spawn_command(cmd)
            .with_context(|| format!("failed to start {}", spec.program.display()))?;
        // The child holds the only slave descriptor; closing ours makes EOF reach the reader.
        drop(pair.slave);
        let pid = child.process_id().map(|p| p as i32);

        let mut reader = pair.master.try_clone_reader().context("pty reader")?;
        let mut writer = pair.master.take_writer().context("pty writer")?;

        let (out_tx, out_rx) = mpsc::channel::<Bytes>(32);
        std::thread::Builder::new()
            .name("pty-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; READ_CHUNK];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            // Blocks when the consumer is slow: backpressure into the PTY.
                            if out_tx
                                .blocking_send(Bytes::copy_from_slice(&buf[..n]))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break, // EIO once the slave side is closed
                    }
                }
            })?;

        let (input_tx, mut input_rx) = mpsc::channel::<Bytes>(64);
        std::thread::Builder::new()
            .name("pty-write".into())
            .spawn(move || {
                while let Some(data) = input_rx.blocking_recv() {
                    if writer
                        .write_all(&data)
                        .and_then(|_| writer.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            })?;

        let (exit_tx, exit_rx) = watch::channel(None);
        std::thread::Builder::new()
            .name("pty-wait".into())
            .spawn(move || {
                let code = child.wait().ok().map(|s| s.exit_code());
                let _ = exit_tx.send(Some(ExitInfo { code }));
            })?;

        Ok((
            Self {
                master: Mutex::new(pair.master),
                input_tx,
                pid,
                run_as: spec.run_as.clone(),
                exit_rx,
            },
            out_rx,
        ))
    }

    pub fn pid(&self) -> Option<i32> {
        self.pid
    }

    /// Queue input for the PTY. Waits (backpressure) if the process is not reading.
    pub async fn write(&self, data: Bytes) -> Result<(), ()> {
        self.input_tx.send(data).await.map_err(|_| ())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let (cols, rows) = clamp_size(cols, rows);
        self.master
            .lock()
            .unwrap()
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("resize failed")
    }

    pub fn size(&self) -> Option<(u16, u16)> {
        self.master
            .lock()
            .unwrap()
            .get_size()
            .ok()
            .map(|s| (s.cols, s.rows))
    }

    pub fn exit_status(&self) -> Option<ExitInfo> {
        *self.exit_rx.borrow()
    }

    pub async fn wait_exit(&self) -> ExitInfo {
        let mut rx = self.exit_rx.clone();
        loop {
            if let Some(e) = *rx.borrow_and_update() {
                return e;
            }
            if rx.changed().await.is_err() {
                return ExitInfo { code: None };
            }
        }
    }

    fn signal_group(&self, sig: i32) {
        if let (Some(pid), Some(user)) = (self.pid, &self.run_as)
            && pid > 0
        {
            // The shell belongs to another account, so only that account (via sudo) may signal it.
            // Its pid is its process group (setsid; sudo hands over without forking).
            let name = match sig {
                libc::SIGHUP => "HUP",
                libc::SIGCONT => "CONT",
                libc::SIGKILL => "KILL",
                _ => "TERM",
            };
            let kill: Vec<OsString> = ["-s", name, "--"].map(OsString::from).into_iter()
                .chain([OsString::from(format!("-{pid}"))])
                .collect();
            let _ = std::process::Command::new(SUDO)
                .args(sudo_args(user, std::path::Path::new("/bin/kill"), &kill))
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            return;
        }
        if let Some(pid) = self.pid
            && pid > 0
        {
            // The child is a session leader (setsid), so its pid is the process group id.
            // SAFETY: plain syscalls with a positive pid; errors (e.g. ESRCH) are ignored.
            unsafe {
                if libc::killpg(pid, sig) != 0 {
                    libc::kill(pid, sig);
                }
            }
        }
    }

    /// Terminate the process group: SIGHUP, then SIGKILL if it is still running after `grace`.
    pub async fn terminate(&self, grace: Duration) -> ExitInfo {
        if let Some(e) = self.exit_status() {
            // Shell gone; clean up any background jobs left in its group.
            self.signal_group(libc::SIGHUP);
            return e;
        }
        self.signal_group(libc::SIGHUP);
        self.signal_group(libc::SIGCONT);
        match tokio::time::timeout(grace, self.wait_exit()).await {
            Ok(e) => e,
            Err(_) => {
                self.signal_group(libc::SIGKILL);
                tokio::time::timeout(Duration::from_secs(2), self.wait_exit())
                    .await
                    .unwrap_or(ExitInfo { code: None })
            }
        }
    }
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        if self.exit_status().is_none() {
            self.signal_group(libc::SIGKILL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh_spec(script: &str) -> PtySpec {
        PtySpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: base_env(),
            cwd: std::env::temp_dir(),
            cols: 80,
            rows: 24,
            run_as: None,
            sandbox: None,
        }
    }

    async fn read_until(rx: &mut mpsc::Receiver<Bytes>, needle: &str) -> String {
        let mut acc = String::new();
        let fut = async {
            while let Some(b) = rx.recv().await {
                acc.push_str(&String::from_utf8_lossy(&b));
                if acc.contains(needle) {
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"));
        acc
    }

    #[tokio::test]
    async fn runs_interactive_shell_and_reports_exit() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec("read line; echo got:$line; exit 3")).unwrap();
        p.write(Bytes::from_static(b"hello\r")).await.unwrap();
        let out = read_until(&mut rx, "got:hello").await;
        assert!(out.contains("got:hello"));
        assert_eq!(p.wait_exit().await.code, Some(3));
    }

    #[tokio::test]
    async fn pty_is_a_tty_and_resizes() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec(
            "stty size; read x; stty size; test -t 0 && echo IS_TTY",
        ))
        .unwrap();
        read_until(&mut rx, "24 80").await;
        p.resize(132, 40).unwrap();
        assert_eq!(p.size(), Some((132, 40)));
        p.write(Bytes::from_static(b"\r")).await.unwrap();
        let out = read_until(&mut rx, "IS_TTY").await;
        assert!(out.contains("40 132"), "{out}");
    }

    #[tokio::test]
    async fn ctrl_c_interrupts_foreground_process() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec(
            "trap 'echo TRAPPED; exit 7' INT; echo READY; while :; do sleep 1; done",
        ))
        .unwrap();
        read_until(&mut rx, "READY").await;
        p.write(Bytes::from_static(b"\x03")).await.unwrap();
        read_until(&mut rx, "TRAPPED").await;
        assert_eq!(p.wait_exit().await.code, Some(7));
    }

    #[tokio::test]
    async fn ctrl_d_ends_cat() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec("cat; echo CAT_DONE")).unwrap();
        p.write(Bytes::from_static(b"\x04")).await.unwrap();
        read_until(&mut rx, "CAT_DONE").await;
        assert_eq!(p.wait_exit().await.code, Some(0));
    }

    #[tokio::test]
    async fn terminate_kills_process_group() {
        let (p, mut rx) =
            PtyProcess::spawn(&sh_spec("trap '' HUP; sleep 300 & echo BG:$!; wait")).unwrap();
        let out = read_until(&mut rx, "\n").await;
        let bg: i32 = out
            .split("BG:")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .expect("background pid");
        let start = std::time::Instant::now();
        p.terminate(Duration::from_millis(500)).await;
        assert!(p.exit_status().is_some());
        assert!(start.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(200)).await;
        // SAFETY: probe only.
        let alive = unsafe { libc::kill(bg, 0) } == 0;
        assert!(!alive, "background child {bg} survived");
    }

    #[test]
    fn sudo_args_keep_the_command_after_the_separator() {
        let a = sudo_args("workstation", std::path::Path::new("/bin/zsh"), &["-l".into(), "-c".into(), "-u root".into()]);
        let a: Vec<_> = a.iter().map(|x| x.to_string_lossy().into_owned()).collect();
        assert_eq!(a, ["-n", "-H", "-u", "workstation", "--", "/bin/zsh", "-l", "-c", "-u root"]);
    }

    #[test]
    fn the_command_line_wraps_the_shell_in_its_sandbox_then_its_account() {
        let mut spec = sh_spec("true");
        spec.program = "/bin/zsh".into();
        spec.args = vec!["-l".into()];
        assert_eq!(command_line(&spec), ("/bin/zsh".into(), vec!["-l".into()]));
        spec.sandbox = Some(Sandbox {
            profile: "/usr/local/etc/sshweb/shell.sb".into(),
            params: vec![("HOME".into(), "/Users/workstation".into()), ("OTLP_PORT".into(), "7683".into())],
        });
        spec.run_as = Some("workstation".into());
        let (program, args) = command_line(&spec);
        let args: Vec<_> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(program, std::path::Path::new(SUDO));
        assert_eq!(args, [
            "-n", "-H", "-u", "workstation", "--", SANDBOX_EXEC, "-f", "/usr/local/etc/sshweb/shell.sb",
            "-D", "HOME=/Users/workstation", "-D", "OTLP_PORT=7683", "/bin/zsh", "-l",
        ]);
    }

    #[test]
    fn without_run_as_the_shell_runs_as_the_gateway() {
        let spec = local_shell_spec(&Config::default(), Some(std::path::Path::new("/bin/sh")), 80, 24).unwrap();
        assert_eq!(spec.run_as, None);
    }

    #[test]
    fn run_as_an_unknown_account_is_refused() {
        let mut cfg = Config::default();
        cfg.local.run_as = Some("no-such-account-sshweb".into());
        let err = local_shell_spec(&cfg, Some(std::path::Path::new("/bin/sh")), 80, 24).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn size_is_clamped() {
        assert_eq!(clamp_size(0, 0), (MIN_COLS, MIN_ROWS));
        assert_eq!(clamp_size(60000, 60000), (MAX_COLS, MAX_ROWS));
    }

    #[test]
    fn local_shell_policy() {
        let cfg = Config::default();
        assert!(
            local_shell_spec(&cfg, Some(std::path::Path::new("/usr/bin/python3")), 80, 24).is_err()
        );
        let spec = local_shell_spec(&cfg, Some(std::path::Path::new("/bin/sh")), 80, 24).unwrap();
        assert_eq!(spec.args, vec![OsString::from("-l")]);
        assert!(
            spec.env
                .iter()
                .any(|(k, v)| k == "TERM" && v == "xterm-256color")
        );
        assert!(!spec.env.iter().any(|(k, _)| k.starts_with("SSHWEB_")));
    }
}
