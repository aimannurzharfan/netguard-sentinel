"""Unit tests for scanner banner fingerprinting (no network required)."""

from scanner.scan import DEFAULT_PORTS, _fingerprint


class TestFingerprint:
    def test_apache_plain_banner(self):
        svc, ver = _fingerprint("Apache/2.4.49 (Unix)", 80)
        assert svc == "Apache httpd"
        assert ver == "2.4.49"

    def test_apache_server_header(self):
        banner = "HTTP/1.0 200 OK\r\nServer: Apache/2.4.49 (Debian)\r\nDate: ..."
        svc, ver = _fingerprint(banner, 80)
        assert svc == "Apache httpd"
        assert ver == "2.4.49"

    def test_openssh_banner(self):
        svc, ver = _fingerprint("SSH-2.0-OpenSSH_7.4", 22)
        assert svc == "OpenSSH"
        assert ver == "7.4"

    def test_openssh_banner_with_patch_suffix(self):
        svc, ver = _fingerprint("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22)
        assert svc == "OpenSSH"
        assert ver == "8.9p1"

    def test_vsftpd_banner_parenthesised(self):
        svc, ver = _fingerprint("220 (vsFTPd 2.3.4)", 21)
        assert svc == "vsftpd"
        assert ver == "2.3.4"

    def test_vsftpd_banner_plain(self):
        svc, ver = _fingerprint("220 vsftpd 2.3.4 ready.", 21)
        assert svc == "vsftpd"
        assert ver == "2.3.4"

    def test_nginx_server_header(self):
        banner = "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"
        svc, ver = _fingerprint(banner, 80)
        assert svc == "nginx"
        assert ver == "1.24.0"

    def test_proftpd_banner(self):
        svc, ver = _fingerprint("220 ProFTPD 1.3.5 Server", 21)
        assert svc == "ProFTPD"
        assert ver == "1.3.5"

    def test_unknown_banner_falls_back_to_port(self):
        svc, ver = _fingerprint("some unknown protocol bytes", 3389)
        assert svc == "RDP"
        assert ver == ""

    def test_empty_banner_uses_port_fallback(self):
        svc, ver = _fingerprint("", 3306)
        assert svc == "MySQL"
        assert ver == ""

    def test_unknown_port_with_unknown_banner(self):
        svc, ver = _fingerprint("garbage", 9999)
        assert svc == ""
        assert ver == ""

    def test_default_ports_covers_key_services(self):
        assert 80 in DEFAULT_PORTS
        assert 22 in DEFAULT_PORTS
        assert 21 in DEFAULT_PORTS
        assert 8080 in DEFAULT_PORTS
        assert 3306 in DEFAULT_PORTS
        assert 443 in DEFAULT_PORTS
