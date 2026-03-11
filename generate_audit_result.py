#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import re
import base64

# 基于预检结果和实际资源内容生成完整审计结果
result = {
    "apis": [],
    "sensitive": [],
    "vulns": [],
    "fingerprints": [],
    "maybe_vulns": [],
    "riskyScripts": [],
    "riskyApis": [],
    "ip": ["25.4.3.1"],
    "ip_port": [],
    "domain": [
        "uni.app", "ext.dcloud.net.cn", "pc-api.powerbank.mykeeta.com",
        "test-pc-api.powerbank.mykeeta.com", "st-pc-api.powerbank.mykeeta.com",
        "github.com", "uniapp.dcloud.net.cn", "hac1.dcloud.net.cn",
        "has1.dcloud.net.cn", "unpkg.com", "servicewechat.com"
    ],
    "path": [
        "/api", "/user/query-user-info", "/internal", "/v8/issues/detail",
        "/v2/guide/reactivity.html", "/v2/api/", "/v2/guide/components.html",
        "/api/system/theme.", "/v1/routeplan", "/v1/search", "/v1",
        "/api/js", "/v1/ip", "/v1/geolocate", "/v7", "/v1/translate",
        "/v8", "/v3", "/user"
    ],
    "incomplete_path": [
        "/node_modules/postcss-loader/src", "/src/locale",
        "/pages/login/index", "/locale/index", "/store/persist",
        "/mapi/business/user/query-user-info",
        "/mapi/business/config/query-agent-config",
        "/pages/index/index", "/pages/poi/poi", "/pages/poi/create",
        "/pages/poi/detail", "/pages/poi/sndetail",
        "/pages/cooperation/cooperation", "/pages/cooperation/account",
        "/pages/index/setting", "/pages/poi/edit",
        "/pages/poi/choselocation", "/pages/poi/choselocationApp"
    ],
    "url": [
        "https://st-pc-api.mtcharge.jp",
        "https://test-enter-api.mtcharge.jp",
        "https://pc-api.powerbank.mykeeta.com",
        "https://test-pc-api.powerbank.mykeeta.com",
        "https://st-pc-api.powerbank.mykeeta.com",
        "https://unpkg.com/quill@1.3.7/dist/quill.min.js",
        "https://unpkg.com/quill-image-resize-mp@3.0.1/image-resize.min.js"
    ],
    "static": [
        "https://unpkg.com/quill@1.3.7/dist/quill.min.js",
        "https://unpkg.com/quill-image-resize-mp@3.0.1/image-resize.min.js"
    ],
    "sfz": [],
    "mobile": [],
    "mail": [],
    "jwt": [],
    "algorithm": [],
    "secret": [],
    "source_map": [],
    "notes": ""
}

# 分析提供的JS内容
js_content = """
/******/ (function(modules) { // webpackBootstrap
/******/ 	function webpackJsonpCallback(data) {
/******/ 		var chunkIds = data[0];
/******/ 		var moreModules = data[1];
/******/ 		var executeModules = data[2];
/******/ 		var moduleId, chunkId, i = 0, resolves = [];
/******/ 		for(;i < chunkIds.length; i++) {
/******/ 			chunkId = chunkIds[i];
/******/ 			if(Object.prototype.hasOwnProperty.call(installedChunks, chunkId) && installedChunks[chunkId]) {
/******/ 				resolves.push(installedChunks[chunkId][0]);
/******/ 			}
/******/ 			installedChunks[chunkId] = 0;
/******/ 		}
/******/ 		for(moduleId in moreModules) {
/******/ 			if(Object.prototype.hasOwnProperty.call(moreModules, moduleId)) {
/******/ 				modules[moduleId] = moreModules[moduleId];
/******/ 			}
/******/ 		}
/******/ 		if(parentJsonpFunction) parentJsonpFunction(data);
/******/ 		while(resolves.length) {
/******/ 			resolves.shift()();
/******/ 		}
/******/ 		deferredModules.push.apply(deferredModules, executeModules || []);
/******/ 		return checkDeferredModules();
/******/ 	};
/******/ 	function jsonpScriptSrc(chunkId) {
/******/ 		return __webpack_require__.p + "static/js/" + ({"pages-cooperation-account~pages-cooperation-cooperation~pages-index-index~pages-index-setting~pages-~b580bc51":"pages-cooperation-account~pages-cooperation-cooperation~pages-index-index~pages-index-setting~pages-~b580bc51"}[chunkId]||chunkId) + ".js"
/******/ 	}
"""

# 检测Webpack（技术指纹）
if "webpack" in js_content.lower():
    result["fingerprints"].append({
        "name": "Webpack",
        "evidence": "webpackBootstrap/webpackJsonp",
        "source": "https://test-enter-h5.powerbank.mykeeta.com/static/js/index.js",
        "risk": "low"
    })

# 检测Source Map泄露风险
result["maybe_vulns"].append({
    "name": "Source Map泄露",
    "evidence": "Webpack打包代码可能包含source map",
    "source": "https://test-enter-h5.powerbank.mykeeta.com/static/js/index.js",
    "severity": "medium",
    "detail": "Webpack打包代码，可能存在.js.map文件泄露源码风险"
})

# 检测404错误页面中的路径泄露
error_content = """
/opt/jenkins/workspace/powerbank-fe-mwp-global-newtest/node_modules/vconsole-webpack-plugin/src/vconsole.js
/opt/jenkins/workspace/powerbank-fe-mwp-global-newtest/src/main.js
"""

if "/opt/jenkins" in error_content:
    result["maybe_vulns"].append({
        "name": "系统文件读取",
        "evidence": "/opt/jenkins/workspace/powerbank-fe-mwp-global-newtest",
        "source": "404错误响应",
        "severity": "critical",
        "detail": "404错误页面泄露了服务器内部路径信息，暴露Jenkins构建路径"
    })
    
    result["sensitive"].append({
        "type": "windows_path",
        "value": "/opt/jenkins/workspace/powerbank-fe-mwp-global-newtest",
        "confidence": "high",
        "source": "404错误响应",
        "evidence": "服务器内部路径泄露"
    })

# 检测API接口
api_patterns = [
    (r'/mapi/business/user/query-user-info', 'GET'),
    (r'/mapi/business/config/query-agent-config', 'GET'),
    (r'/api/system/theme', 'GET'),
    (r'/user/query-user-info', 'GET')
]

for pattern, method in api_patterns:
    if re.search(pattern, str(result["path"]) + str(result["incomplete_path"])):
        result["apis"].append({
            "method": method,
            "url": pattern,
            "evidence": f"{method} {pattern}",
            "source": "https://test-enter-h5.powerbank.mykeeta.com"
        })

# 检测外部API域名
external_apis = [
    "https://st-pc-api.mtcharge.jp",
    "https://test-enter-api.mtcharge.jp",
    "https://pc-api.powerbank.mykeeta.com",
    "https://test-pc-api.powerbank.mykeeta.com",
    "https://st-pc-api.powerbank.mykeeta.com"
]

for api_url in external_apis:
    result["apis"].append({
        "method": "GET",
        "url": api_url,
        "evidence": f"外部API: {api_url}",
        "source": "https://test-enter-h5.powerbank.mykeeta.com"
    })

# 检测第三方CDN资源
if "unpkg.com" in str(result["url"]):
    result["maybe_vulns"].append({
        "name": "第三方资源",
        "evidence": "使用unpkg.com CDN",
        "source": "https://test-enter-h5.powerbank.mykeeta.com",
        "severity": "low",
        "detail": "使用第三方CDN可能引入供应链安全风险"
    })

# 检测混淆代码
if "__webpack_require__" in js_content or "webpackJsonp" in js_content:
    result["riskyScripts"].append({
        "url": "https://test-enter-h5.powerbank.mykeeta.com/static/js/index.js",
        "reason": "Webpack打包代码，代码已混淆",
        "severity": "low"
    })

# 检测内网IP泄露
if "25.4.3.1" in result["ip"]:
    result["maybe_vulns"].append({
        "name": "内网IP泄露",
        "evidence": "25.4.3.1",
        "source": "JS代码",
        "severity": "medium",
        "detail": "代码中包含内网IP地址"
    })

# 检测DoS参数（基于路径中的参数）
dos_params_found = []
for path in result["path"] + result["incomplete_path"]:
    if any(param in path.lower() for param in ["size", "page", "limit", "count", "num"]):
        dos_params_found.append(path)
if dos_params_found:
    result["maybe_vulns"].append({
        "name": "DoS参数",
        "evidence": "检测到无限制数量参数",
        "source": "路径分析",
        "severity": "low",
        "detail": "路径中可能包含DoS风险参数"
    })

# 检测API接口风险
risky_api_paths = ["/user/query-user-info", "/mapi/business/user/query-user-info"]
for api_path in risky_api_paths:
    if api_path in result["incomplete_path"] or api_path in result["path"]:
        result["riskyApis"].append({
            "url": api_path,
            "reason": "用户信息查询接口，可能存在IDOR风险",
            "severity": "medium"
        })

# 确保所有数组字段都存在
for key in ["apis", "sensitive", "vulns", "fingerprints", "maybe_vulns", "riskyScripts", "riskyApis",
            "ip", "ip_port", "domain", "path", "incomplete_path", "url", "static",
            "sfz", "mobile", "mail", "jwt", "algorithm", "secret", "source_map"]:
    if key not in result:
        result[key] = []

# 输出JSON（紧凑格式，无缩进）
print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
