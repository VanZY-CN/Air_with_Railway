#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import json
import requests
from urllib.parse import urljoin, urlparse
from collections import defaultdict

class SecurityAuditor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.html_content = ""
        self.js_contents = {}
        self.results = {
            "apis": [],
            "sensitive": [],
            "vulns": [],
            "fingerprints": [],
            "maybe_vulns": [],
            "riskyScripts": [],
            "riskyApis": [],
            "ip": [],
            "ip_port": [],
            "domain": [],
            "path": [],
            "incomplete_path": [],
            "url": [],
            "static": [],
            "sfz": [],
            "mobile": [],
            "mail": [],
            "jwt": [],
            "algorithm": [],
            "secret": [],
            "source_map": [],
            "notes": ""
        }
    
    def fetch_page(self):
        """获取目标页面"""
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            resp = requests.get(self.target_url, headers=headers, timeout=30, verify=False)
            self.html_content = resp.text
            return True
        except Exception as e:
            self.results["notes"] = f"获取页面失败: {str(e)}"
            return False
    
    def extract_js_urls(self):
        """提取JS文件URL"""
        js_urls = []
        # 从HTML中提取script标签
        script_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
        matches = re.findall(script_pattern, self.html_content, re.IGNORECASE)
        for match in matches:
            if match.startswith('//'):
                match = 'https:' + match
            elif match.startswith('/'):
                match = self.base_url + match
            elif not match.startswith('http'):
                match = urljoin(self.base_url, match)
            js_urls.append(match)
        return js_urls
    
    def fetch_js_files(self, js_urls):
        """获取JS文件内容"""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        for url in js_urls[:10]:  # 限制前10个文件
            try:
                resp = requests.get(url, headers=headers, timeout=15, verify=False)
                if resp.status_code == 200:
                    self.js_contents[url] = resp.text[:500000]  # 限制大小
            except:
                pass
    
    def detect_fingerprints(self):
        """维度1: 技术指纹检测"""
        content = self.html_content + "\n".join(self.js_contents.values())
        
        # Shiro
        if re.search(r'rememberMe\s*=|deleteMe\s*=', content, re.I):
            self.results["fingerprints"].append({
                "name": "Shiro",
                "evidence": "Cookie含rememberMe或deleteMe",
                "source": "HTML/JS",
                "risk": "critical"
            })
        
        # JWT
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        jwt_matches = re.findall(jwt_pattern, content)
        for jwt in jwt_matches[:5]:
            try:
                import base64
                parts = jwt.split('.')
                if len(parts) >= 2:
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8', errors='ignore'))
                    alg = header.get('alg', '')
                    risk = "high" if alg in ['none', 'HS256'] else "medium"
                    self.results["fingerprints"].append({
                        "name": "JWT",
                        "evidence": f"JWT Token alg={alg}",
                        "source": "JS",
                        "risk": risk
                    })
            except:
                pass
        
        # Swagger UI
        if re.search(r'swagger-ui\.html|"swagger":|swaggerUi|swaggerVersion', content, re.I):
            self.results["fingerprints"].append({
                "name": "Swagger UI",
                "evidence": "检测到Swagger相关特征",
                "source": "HTML/JS",
                "risk": "medium"
            })
        
        # Ueditor
        if re.search(r'ueditor\.config\.js|ueditor\.all\.js', content, re.I):
            self.results["fingerprints"].append({
                "name": "Ueditor",
                "evidence": "检测到Ueditor文件",
                "source": "HTML/JS",
                "risk": "high"
            })
        
        # Druid
        if re.search(r'Druid Stat Index|druid/index', content, re.I):
            self.results["fingerprints"].append({
                "name": "Druid",
                "evidence": "检测到Druid监控页",
                "source": "HTML/JS",
                "risk": "medium"
            })
        
        # PDF.js
        if re.search(r'pdf\.worker', content, re.I):
            self.results["fingerprints"].append({
                "name": "PDF.js",
                "evidence": "检测到PDF.js worker",
                "source": "JS",
                "risk": "medium"
            })
        
        # Vite DevMode
        if re.search(r'/@vite/client', content):
            self.results["fingerprints"].append({
                "name": "Vite DevMode",
                "evidence": "/@vite/client出现在生产页面",
                "source": "HTML",
                "risk": "critical"
            })
    
    def detect_maybe_vulns(self):
        """维度2: 潜在漏洞检测"""
        content = self.html_content + "\n".join(self.js_contents.values())
        
        # Java反序列化
        if re.search(r'javax\.faces\.ViewState', content, re.I):
            self.results["maybe_vulns"].append({
                "name": "Java反序列化",
                "evidence": "javax.faces.ViewState",
                "source": "HTML/JS",
                "severity": "high",
                "detail": "可能存在Java反序列化漏洞"
            })
        
        # Debug参数
        debug_params = ['access=', '/admin=', '/debug=', '/exec=', '/shell=', '/root=', '/enable=', '/reset=']
        for param in debug_params:
            if re.search(re.escape(param), content, re.I):
                self.results["maybe_vulns"].append({
                    "name": "Debug参数",
                    "evidence": param,
                    "source": "JS",
                    "severity": "medium",
                    "detail": "检测到危险调试参数"
                })
                break
        
        # SSRF/开放重定向
        ssrf_pattern = r'=\s*(https?://[^\s"\'<>]+)'
        ssrf_matches = re.findall(ssrf_pattern, content)
        if ssrf_matches:
            self.results["maybe_vulns"].append({
                "name": "SSRF/开放重定向",
                "evidence": f"参数值包含URL: {ssrf_matches[0][:50]}",
                "source": "JS",
                "severity": "medium",
                "detail": "可能存在SSRF或开放重定向风险"
            })
        
        # 文件上传
        if re.search(r'type\s*=\s*["\']file["\']', content, re.I):
            self.results["maybe_vulns"].append({
                "name": "文件上传",
                "evidence": "type=\"file\"表单",
                "source": "HTML",
                "severity": "medium",
                "detail": "检测到文件上传表单"
            })
        
        # DoS参数
        dos_params = ['size=', 'page=', 'limit=', 'count=', 'num=']
        for param in dos_params:
            if re.search(re.escape(param), content, re.I):
                self.results["maybe_vulns"].append({
                    "name": "DoS参数",
                    "evidence": param,
                    "source": "JS",
                    "severity": "low",
                    "detail": "无限制数量参数可能导致DoS"
                })
                break
        
        # 系统文件读取
        if re.search(r'/root:|/bin/bash|for 16-bit app', content, re.I):
            self.results["maybe_vulns"].append({
                "name": "系统文件读取",
                "evidence": "检测到系统路径",
                "source": "JS",
                "severity": "critical",
                "detail": "可能存在系统文件读取风险"
            })
        
        # Source Map泄露
        source_map_pattern = r'\.js\.map["\']?'
        if re.search(source_map_pattern, content):
            self.results["maybe_vulns"].append({
                "name": "Source Map泄露",
                "evidence": ".js.map路径",
                "source": "JS",
                "severity": "medium",
                "detail": "源码泄露风险"
            })
    
    def extract_basic_info(self):
        """维度3: 基础信息提取"""
        content = self.html_content + "\n".join(self.js_contents.values())
        
        # 邮箱
        mail_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        mails = list(set(re.findall(mail_pattern, content)))
        self.results["mail"] = [m for m in mails if not m.endswith('.png') and not m.endswith('.jpg')][:20]
        
        # 身份证
        sfz_pattern = r'\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'
        self.results["sfz"] = list(set(re.findall(sfz_pattern, content)))[:10]
        
        # 手机号
        mobile_pattern = r'\b1[3-9]\d{9}\b'
        self.results["mobile"] = list(set(re.findall(mobile_pattern, content)))[:20]
        
        # 内网IP
        ip_pattern = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b'
        self.results["ip"] = list(set(re.findall(ip_pattern, content)))[:20]
        
        # IP:端口
        ip_port_pattern = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1):\d{1,5}\b'
        self.results["ip_port"] = list(set(re.findall(ip_port_pattern, content)))[:20]
        
        # 域名
        domain_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, content)
        domains = [d[0] for d in domains if not d[0].startswith('http')]
        # 过滤常见域名
        exclude_domains = ['w3.org', 'github.com', 'google.com', 'example.com']
        self.results["domain"] = [d for d in list(set(domains))[:100] if not any(ex in d for ex in exclude_domains)]
        
        # JWT
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        self.results["jwt"] = list(set(re.findall(jwt_pattern, content)))[:10]
        
        # 加密算法
        algorithms = ['MD5', 'AES', 'RSA', 'EC', 'SHA256', 'SHA224', 'HMAC', 'PBKDF2', 'DES', '3DES', 'Blowfish', 'SHA512', 'SHA384', 'RC4', 'SHA1', 'SHA3']
        found_algorithms = []
        for alg in algorithms:
            if re.search(r'\b' + re.escape(alg) + r'\b', content, re.I):
                found_algorithms.append(alg)
        self.results["algorithm"] = list(set(found_algorithms))
    
    def detect_sensitive_info(self):
        """维度4: 敏感信息检测"""
        content = self.html_content + "\n".join(self.js_contents.values())
        
        # 云密钥
        cloud_key_patterns = [
            (r'access_key_id\s*[:=]\s*["\']([^"\']+)["\']', 'cloud_key', 'high'),
            (r'access_key_secret\s*[:=]\s*["\']([^"\']+)["\']', 'cloud_key', 'high'),
            (r'LTAI[^"\'\s]+', 'cloud_key', 'high'),
        ]
        for pattern, stype, conf in cloud_key_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches[:3]:
                self.results["sensitive"].append({
                    "type": stype,
                    "value": match[:50] if isinstance(match, str) else match[0][:50],
                    "confidence": conf,
                    "source": "JS",
                    "evidence": pattern
                })
        
        # Windows路径
        if re.search(r'[C-Z]:\\[^"\']+', content):
            self.results["sensitive"].append({
                "type": "windows_path",
                "value": "Windows路径",
                "confidence": "medium",
                "source": "JS",
                "evidence": "检测到Windows路径"
            })
        
        # 密码字段
        password_patterns = [
            r'password\s*[:=]\s*["\']([^"\']{3,})["\']',
            r'passwd\s*[:=]\s*["\']([^"\']{3,})["\']',
            r'pwd\s*[:=]\s*["\']([^"\']{3,})["\']',
        ]
        for pattern in password_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches[:3]:
                if match and match not in ['', 'null', 'undefined']:
                    self.results["sensitive"].append({
                        "type": "password_field",
                        "value": match[:30],
                        "confidence": "high",
                        "source": "JS",
                        "evidence": pattern
                    })
        
        # 用户名字段
        username_patterns = [
            r'username\s*[:=]\s*["\']([^"\']{2,})["\']',
            r'user\s*[:=]\s*["\']([^"\']{2,})["\']',
            r'account\s*[:=]\s*["\']([^"\']{2,})["\']',
        ]
        for pattern in username_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches[:3]:
                if match and match not in ['', 'null', 'undefined']:
                    self.results["sensitive"].append({
                        "type": "username_field",
                        "value": match[:30],
                        "confidence": "medium",
                        "source": "JS",
                        "evidence": pattern
                    })
        
        # 企业微信
        if re.search(r'corpid\s*[:=]\s*["\']([^"\']+)["\']|corpsecret\s*[:=]\s*["\']([^"\']+)["\']', content, re.I):
            self.results["sensitive"].append({
                "type": "wecom_key",
                "value": "企业微信密钥",
                "confidence": "high",
                "source": "JS",
                "evidence": "corpid/corpsecret"
            })
        
        # JDBC连接串
        jdbc_pattern = r'jdbc:(mysql|oracle|postgresql)://[^"\'\s]+'
        jdbc_matches = re.findall(jdbc_pattern, content, re.I)
        if jdbc_matches:
            self.results["sensitive"].append({
                "type": "jdbc",
                "value": jdbc_matches[0][:50],
                "confidence": "high",
                "source": "JS",
                "evidence": "JDBC连接串"
            })
        
        # Auth泄露
        auth_patterns = [
            r'Basic\s+[A-Za-z0-9+/=]+',
            r'Bearer\s+[A-Za-z0-9._-]+',
        ]
        for pattern in auth_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches[:3]:
                self.results["sensitive"].append({
                    "type": "auth_header",
                    "value": match[:30],
                    "confidence": "high",
                    "source": "JS",
                    "evidence": pattern
                })
        
        # 通用敏感字段
        sensitive_fields = ['key=', 'secret=', 'token=', 'config=', 'auth=', 'ticket=']
        for field in sensitive_fields:
            pattern = re.escape(field) + r'\s*[:=]\s*["\']([^"\']{3,})["\']'
            matches = re.findall(pattern, content, re.I)
            for match in matches[:2]:
                if match and match not in ['', 'null', 'undefined']:
                    self.results["sensitive"].append({
                        "type": "sensitive_field",
                        "value": f"{field}{match[:20]}",
                        "confidence": "medium",
                        "source": "JS",
                        "evidence": field
                    })
    
    def extract_apis_and_paths(self):
        """维度5: 接口与路径提取"""
        content = self.html_content + "\n".join(self.js_contents.values())
        
        # API接口 (fetch/axios/$http/ajax/XHR)
        api_patterns = [
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'GET'),
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', None),
            (r'\$http\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', None),
            (r'ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'GET'),
            (r'\.open\s*\(\s*["\']([A-Z]+)["\'][^,]+,\s*["\']([^"\']+)["\']', None),
            (r'url\s*:\s*["\']([^"\']+)["\']', 'GET'),
            (r'["\'](/api/[^"\']+|/v\d+/[^"\']+)["\']', 'GET'),
        ]
        
        seen_apis = set()
        for pattern, default_method in api_patterns:
            matches = re.finditer(pattern, content, re.I | re.MULTILINE)
            for match in matches:
                if default_method:
                    method = default_method
                    url = match.group(1)
                elif len(match.groups()) == 2:
                    method = match.group(1).upper() if match.group(1) else 'GET'
                    url = match.group(2)
                else:
                    method = match.group(1).upper() if match.group(1) else 'GET'
                    url = match.group(2) if len(match.groups()) > 1 else match.group(1)
                
                if url and (url.startswith('/api/') or url.startswith('/v')):
                    api_key = f"{method}:{url}"
                    if api_key not in seen_apis:
                        seen_apis.add(api_key)
                        self.results["apis"].append({
                            "method": method,
                            "url": url,
                            "evidence": match.group(0)[:100],
                            "source": "JS"
                        })
        
        # 路径提取 - 更全面的模式
        path_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'url:\s*["\'](/api/[^"\']+|/v\d+/[^"\']+)["\']',
        ]
        paths = set()
        for pattern in path_patterns:
            matches = re.findall(pattern, content, re.I)
            paths.update(matches)
        self.results["path"] = sorted(list(paths))[:200]
        
        # 相对路径
        incomplete_pattern = r'["\'](\.\.?/[^"\']+)["\']'
        incomplete_paths = re.findall(incomplete_pattern, content)
        self.results["incomplete_path"] = list(set(incomplete_paths))[:100]
        
        # 完整URL
        url_pattern = r'https?://[^\s"\'<>\)]+'
        urls = re.findall(url_pattern, content)
        self.results["url"] = list(set(urls))[:200]
        
        # Source Map
        source_map_pattern = r'https?://[^"\'\s]+\.js\.map'
        source_maps = re.findall(source_map_pattern, content)
        self.results["source_map"] = list(set(source_maps))[:20]
        
        # 风险脚本
        for js_url, js_content in self.js_contents.items():
            if len(js_content) > 100000:  # 大文件
                self.results["riskyScripts"].append({
                    "url": js_url,
                    "reason": "文件过大，可能包含敏感信息",
                    "severity": "medium"
                })
            if re.search(r'eval\s*\(|Function\s*\(|setTimeout\s*\(["\']|setInterval\s*\(["\']', js_content):
                self.results["riskyScripts"].append({
                    "url": js_url,
                    "reason": "包含eval或动态代码执行",
                    "severity": "high"
                })
        
        # 风险API
        risky_api_patterns = [
            (r'/api/[^"\']*(delete|remove|drop|clear)', 'high', '删除操作'),
            (r'/api/[^"\']*(admin|root|super)', 'high', '管理员接口'),
            (r'/api/[^"\']*(password|secret|key)', 'high', '敏感信息接口'),
        ]
        seen_risky = set()
        for pattern, severity, reason in risky_api_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches[:5]:
                url = match if isinstance(match, str) else match[0]
                if url not in seen_risky:
                    seen_risky.add(url)
                    self.results["riskyApis"].append({
                        "url": url,
                        "reason": reason,
                        "severity": severity
                    })
    
    def run_audit(self):
        """执行完整审计"""
        if not self.fetch_page():
            return
        
        js_urls = self.extract_js_urls()
        self.fetch_js_files(js_urls)
        
        self.detect_fingerprints()
        self.detect_maybe_vulns()
        self.extract_basic_info()
        self.detect_sensitive_info()
        self.extract_apis_and_paths()
        
        return self.results

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    auditor = SecurityAuditor("https://uav.mykeeta.com/")
    results = auditor.run_audit()
    print(json.dumps(results, ensure_ascii=False, indent=2))
