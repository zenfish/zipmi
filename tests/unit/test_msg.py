"""_msg: leveled colored diagnostics on stderr (results stay on stdout)."""


def test_levels_plain_go_to_stderr_aligned(capsys):
    from zipmi import _msg
    _msg.configure(False)                     # force color off
    try:
        _msg.info("hello")
        _msg.warn("careful")
        _msg.error("boom")
        _msg.ok("done")
    finally:
        _msg.configure(None)
    cap = capsys.readouterr()
    assert cap.out == ""                       # diagnostics never touch stdout
    # tags padded to the widest ([error]=7) + 1 gap, so messages line up
    assert cap.err.splitlines() == [
        "[info]  hello",
        "[warn]  careful",
        "[error] boom",
        "[ok]    done",
    ]


def test_color_forced_on_wraps_tag_in_ansi(capsys):
    from zipmi import _msg
    _msg.configure(True)
    try:
        _msg.error("x")
    finally:
        _msg.configure(None)
    err = capsys.readouterr().err
    assert "\x1b[" in err and "[error]" in err and err.endswith("x\n")
