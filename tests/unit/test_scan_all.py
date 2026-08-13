"""scan `all` / `unauth` composition + per-step isolation."""
import types


def _patch_probes(monkeypatch):
    from zipmi.cli import zipmi as z
    ran = []
    for name, attr in (("asf", "cmd_scan_asf_ping"), ("auth", "cmd_scan_auth_caps"),
                       ("cs", "cmd_scan_cipher_suites"), ("c0", "cmd_scan_cipher_zero"),
                       ("um", "cmd_user_matrix_list")):
        monkeypatch.setattr(z, attr, (lambda n: lambda a: (ran.append(n), 0)[1])(name))
    return z, ran


def test_unauth_runs_only_sessionless_trio(monkeypatch):
    z, ran = _patch_probes(monkeypatch)
    rc = z.cmd_scan_unauth(types.SimpleNamespace())
    assert ran == ["asf", "auth", "cs"]        # no cipher-zero, no user-matrix
    assert rc == 0


def test_all_means_all_includes_cipher_zero(monkeypatch):
    z, ran = _patch_probes(monkeypatch)
    rc = z.cmd_scan_all(types.SimpleNamespace(json=False))
    assert ran[:3] == ["asf", "auth", "cs"]
    assert "um" in ran and "c0" in ran         # authenticated probes run too
    assert rc == 0


def test_all_json_runs_every_step_and_aggregates(monkeypatch, capsys):
    # Under --json scan now runs ALL steps (no longer grid-only) and aggregates
    # each step's JSON into one {steps:[...]} envelope.
    import json
    z, ran = _patch_probes(monkeypatch)
    z.cmd_scan_all(types.SimpleNamespace(json=True))
    assert ran == ["asf", "auth", "cs", "um", "c0"]     # every step runs
    d = json.loads(capsys.readouterr().out)             # single envelope, parses
    assert [s["step"] for s in d["steps"]] == [
        "asf-ping", "auth-caps", "cipher-suites", "user-matrix", "cipher-zero"]


def test_run_scan_steps_isolates_failures(capsys):
    from zipmi.cli import zipmi as z
    ran = []

    def ok(a):
        ran.append("ok"); return 0

    def boom(a):
        ran.append("boom"); raise RuntimeError("nope")

    def two(a):
        ran.append("two"); return 2

    rc = z._run_scan_steps(object(), [("a", ok), ("b", boom), ("c", two)])
    assert ran == ["ok", "boom", "two"]        # boom did not stop c
    assert rc == (0 | 1 | 2)                    # boom -> rc|=1, two -> rc|=2
    assert "[error]" in capsys.readouterr().err
