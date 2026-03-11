#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import re
from typing import List, Dict, Any

def analyze_security(content: str, source: str) -> Dict[str, Any]:
    """安全审计分析函数"""
    result = {
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
    
    # 维度1: 技术指纹检测
    # Shiro
    if re.search(r'rememberMe\s*=', content, re.I) or re.search(r'deleteMe\s*=', content, re.I):
        result["fingerprints"].append({
            "name": "Shiro",
            "evidence": "Cookie含rememberMe或deleteMe",
            "source": source,
            "risk": "critical"
        })
    
    # JWT
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    jwt_matches = re.findall(jwt_pattern, content)
    for jwt in jwt_matches:
        try:
            import base64
            parts = jwt.split('.')
            if len(parts) >= 2:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8'))
                alg = header.get('alg', '')
                risk = "high" if alg in ['none', 'HS256'] else "medium"
                result["fingerprints"].append({
                    "name": "JWT",
                    "evidence": f"JWT Token alg={alg}",
                    "source": source,
                    "risk": risk
                })
                result["jwt"].append(jwt)
        except:
            result["jwt"].append(jwt)
    
    # Swagger UI
    if re.search(r'swagger-ui\.html|"swagger":|swaggerUi|swaggerVersion', content, re.I):
        result["fingerprints"].append({
            "name": "Swagger UI",
            "evidence": "检测到Swagger UI相关标识",
            "source": source,
            "risk": "medium"
        })
    
    # Ueditor
    if re.search(r'ueditor\.config\.js|ueditor\.all\.js', content, re.I):
        result["fingerprints"].append({
            "name": "Ueditor",
            "evidence": "检测到Ueditor相关文件",
            "source": source,
            "risk": "high"
        })
    
    # Druid
    if re.search(r'Druid Stat Index', content, re.I):
        result["fingerprints"].append({
            "name": "Druid",
            "evidence": "Druid Stat Index",
            "source": source,
            "risk": "medium"
        })
    
    # PDF.js
    if re.search(r'pdf\.worker', content, re.I):
        result["fingerprints"].append({
            "name": "PDF.js",
            "evidence": "pdf.worker",
            "source": source,
            "risk": "medium"
        })
    
    # Vite DevMode
    if re.search(r'/@vite/client', content):
        result["fingerprints"].append({
            "name": "Vite DevMode",
            "evidence": "/@vite/client出现在生产页面",
            "source": source,
            "risk": "critical"
        })
    
    # 维度2: 潜在漏洞检测
    # Java反序列化
    if re.search(r'javax\.faces\.ViewState', content):
        result["maybe_vulns"].append({
            "name": "Java反序列化",
            "evidence": "javax.faces.ViewState",
            "source": source,
            "severity": "high",
            "detail": "JSF ViewState可能存在反序列化漏洞"
        })
    
    # Debug参数
    debug_params = ['access', 'admin', 'debug', 'exec', 'shell', 'root', 'enable', 'reset']
    for param in debug_params:
        pattern = rf'{param}\s*=\s*["\']?[^"\'\s]+'
        if re.search(pattern, content, re.I):
            result["maybe_vulns"].append({
                "name": "Debug参数",
                "evidence": f"{param}=",
                "source": source,
                "severity": "medium",
                "detail": f"检测到危险参数名: {param}"
            })
    
    # SSRF/开放重定向
    ssrf_pattern = r'=\s*(https?://[^\s"\'<>]+)'
    ssrf_matches = re.findall(ssrf_pattern, content)
    for match in ssrf_matches[:10]:  # 限制数量
        result["maybe_vulns"].append({
            "name": "SSRF/开放重定向",
            "evidence": f"={match}",
            "source": source,
            "severity": "medium",
            "detail": "参数值包含URL，可能存在SSRF或开放重定向"
        })
    
    # 文件上传
    if re.search(r'type\s*=\s*["\']file["\']', content, re.I):
        result["maybe_vulns"].append({
            "name": "文件上传",
            "evidence": "type=\"file\"",
            "source": source,
            "severity": "medium",
            "detail": "检测到文件上传表单"
        })
    
    # DoS参数
    dos_params = ['size', 'page', 'limit', 'count', 'num']
    for param in dos_params:
        pattern = rf'{param}\s*=\s*["\']?[^"\'\s]+'
        if re.search(pattern, content, re.I):
            result["maybe_vulns"].append({
                "name": "DoS参数",
                "evidence": f"{param}=",
                "source": source,
                "severity": "low",
                "detail": f"检测到无限制数量参数: {param}"
            })
    
    # 系统文件读取
    if re.search(r'/root:|/bin/bash|for 16-bit app', content):
        result["maybe_vulns"].append({
            "name": "系统文件读取",
            "evidence": "检测到系统路径",
            "source": source,
            "severity": "critical",
            "detail": "可能存在系统文件读取风险"
        })
    
    # Source Map泄露
    source_map_pattern = r'([^\s"\'<>]+\.js\.map)'
    source_map_matches = re.findall(source_map_pattern, content)
    for sm in source_map_matches[:20]:
        result["maybe_vulns"].append({
            "name": "Source Map泄露",
            "evidence": sm,
            "source": source,
            "severity": "medium",
            "detail": "源码映射文件泄露"
        })
        if sm.startswith('http'):
            result["source_map"].append(sm)
    
    # 维度3: 基础信息提取
    # 邮箱
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = list(set(re.findall(email_pattern, content)))
    result["mail"].extend(emails[:50])
    
    # 身份证
    sfz_pattern = r'\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'
    sfz_list = list(set(re.findall(sfz_pattern, content)))
    result["sfz"].extend([s[0] if isinstance(s, tuple) else s for s in sfz_list[:20]])
    
    # 手机号
    mobile_pattern = r'\b1[3-9]\d{9}\b'
    mobiles = list(set(re.findall(mobile_pattern, content)))
    result["mobile"].extend(mobiles[:50])
    
    # 内网IP
    ip_pattern = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b'
    ips = list(set(re.findall(ip_pattern, content)))
    result["ip"].extend([ip[0] if isinstance(ip, tuple) else ip for ip in ips[:50]])
    
    # IP端口
    ip_port_pattern = r'\b((?:10\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168|127\.0\.0)\.\d{1,3}\.\d{1,3}):(\d{1,5})\b'
    ip_ports = re.findall(ip_port_pattern, content)
    result["ip_port"].extend([f"{ip}:{port}" for ip, port in ip_ports[:20]])
    
    # 域名
    domain_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = list(set(re.findall(domain_pattern, content)))
    result["domain"].extend([d[0] if isinstance(d, tuple) else d for d in domains[:100]])
    
    # 加密算法
    algorithm_pattern = r'\b(MD5|SHA1|SHA256|SHA512|AES|DES|RSA|DSA|ECDSA|HMAC|BCrypt|PBKDF2)\b'
    algorithms = list(set(re.findall(algorithm_pattern, content, re.I)))
    result["algorithm"].extend(algorithms[:20])
    
    # 维度4: 敏感信息
    # 云密钥
    if re.search(r'access_key_id|access_key_secret|LTAI', content, re.I):
        matches = re.findall(r'(access_key_id|access_key_secret|LTAI[^\s"\'<>]+)', content, re.I)
        for match in matches[:10]:
            result["sensitive"].append({
                "type": "cloud_key",
                "value": match[:50],
                "confidence": "high",
                "source": source,
                "evidence": match[:100]
            })
    
    # Windows路径
    win_path_pattern = r'[CD]:\\[^\s"\'<>]+'
    win_paths = re.findall(win_path_pattern, content)
    for path in win_paths[:10]:
        result["sensitive"].append({
            "type": "windows_path",
            "value": path,
            "confidence": "medium",
            "source": source,
            "evidence": path
        })
    
    # 密码字段
    password_pattern = r'(password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']'
    password_matches = re.findall(password_pattern, content, re.I)
    for key, value in password_matches[:10]:
        if value and len(value) > 0:
            result["sensitive"].append({
                "type": "password_field",
                "value": value[:30],
                "confidence": "high",
                "source": source,
                "evidence": f"{key}={value[:50]}"
            })
    
    # 用户名字段
    username_pattern = r'(username|user|account)\s*[:=]\s*["\']([^"\']+)["\']'
    username_matches = re.findall(username_pattern, content, re.I)
    for key, value in username_matches[:10]:
        if value and len(value) > 0:
            result["sensitive"].append({
                "type": "username_field",
                "value": value[:30],
                "confidence": "medium",
                "source": source,
                "evidence": f"{key}={value[:50]}"
            })
    
    # 企业微信
    if re.search(r'corpid|corpsecret', content, re.I):
        matches = re.findall(r'(corpid|corpsecret)\s*[:=]\s*["\']([^"\']+)["\']', content, re.I)
        for key, value in matches[:10]:
            result["sensitive"].append({
                "type": "wecom_key",
                "value": value[:30],
                "confidence": "high",
                "source": source,
                "evidence": f"{key}={value[:50]}"
            })
    
    # JDBC连接串
    jdbc_pattern = r'jdbc:(mysql|oracle|postgresql|sqlserver)://[^\s"\'<>]+'
    jdbc_matches = re.findall(jdbc_pattern, content, re.I)
    for match in jdbc_matches[:10]:
        result["sensitive"].append({
            "type": "jdbc",
            "value": match[:50],
            "confidence": "high",
            "source": source,
            "evidence": match[:100]
        })
    
    # Auth泄露
    auth_pattern = r'(Basic|Bearer)\s+[A-Za-z0-9+/=]+'
    auth_matches = re.findall(auth_pattern, content)
    for match in auth_matches[:10]:
        result["sensitive"].append({
            "type": "auth_header",
            "value": match[:50],
            "confidence": "high",
            "source": source,
            "evidence": match[:100]
        })
    
    # 通用敏感字段
    sensitive_fields = ['key', 'secret', 'token', 'config', 'auth', 'ticket']
    for field in sensitive_fields:
        pattern = rf'{field}\s*[:=]\s*["\']([^"\']+)["\']'
        matches = re.findall(pattern, content, re.I)
        for value in matches[:5]:
            if value and len(value) > 0:
                result["sensitive"].append({
                    "type": "sensitive_field",
                    "value": value[:30],
                    "confidence": "medium",
                    "source": source,
                    "evidence": f"{field}={value[:50]}"
                })
    
    # 维度5: 接口与路径
    # API提取 (fetch/axios/$http/ajax/XHR)
    api_patterns = [
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'\$http\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'ajax\s*\(\s*["\']([^"\']+)["\']',
        r'\.open\s*\(\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in api_patterns:
        matches = re.findall(pattern, content, re.I)
        for match in matches:
            if isinstance(match, tuple):
                if len(match) == 2:
                    method = match[0].upper()
                    url = match[1]
                else:
                    url = match[0] if match[0] else match[1]
                    method = "GET"
            else:
                url = match
                method = "GET"
            
            if url and not url.startswith('data:'):
                result["apis"].append({
                    "method": method,
                    "url": url,
                    "evidence": f"{method} {url}",
                    "source": source
                })
    
    # 路径提取
    path_pattern = r'["\'](/api/|/v\d+/|/v\d+/)[^"\']*["\']'
    paths = re.findall(path_pattern, content)
    result["path"].extend(list(set(paths))[:50])
    
    # 相对路径
    incomplete_pattern = r'["\'](\./|\.\./)[^"\']*["\']'
    incomplete_paths = re.findall(incomplete_pattern, content)
    result["incomplete_path"].extend(list(set(incomplete_paths))[:50])
    
    # 完整URL
    url_pattern = r'https?://[^\s"\'<>]+'
    urls = re.findall(url_pattern, content)
    result["url"].extend(list(set(urls))[:100])
    
    # 混淆/危险脚本检测
    if re.search(r'eval\s*\(|Function\s*\(|setTimeout\s*\(["\']|setInterval\s*\(["\']', content):
        result["riskyScripts"].append({
            "url": source,
            "reason": "包含eval或动态代码执行",
            "severity": "high"
        })
    
    # 去重
    for key in ["ip", "ip_port", "domain", "path", "incomplete_path", "url", "mail", "sfz", "mobile", "jwt", "algorithm", "source_map"]:
        result[key] = list(set(result[key]))
    
    return result

# 读取资源内容
resources = [
    {
        "url": "https://test-enter-h5.powerbank.mykeeta.com/static/js/index.js",
        "content": """/******/ (function(modules) { // webpackBootstrap
/******/ 	// install a JSONP callback for chunk loading
/******/ 	function webpackJsonpCallback(data) {
/******/ 		var chunkIds = data[0];
/******/ 		var moreModules = data[1];
/******/ 		var executeModules = data[2];
/******/
/******/ 		// add "moreModules" to the modules object,
/******/ 		// then flag all "chunkIds" as loaded and fire callback
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
/******/
/******/ 		while(resolves.length) {
/******/ 			resolves.shift()();
/******/ 		}
/******/
/******/ 		// add entry modules from loaded chunk to deferred list
/******/ 		deferredModules.push.apply(deferredModules, executeModules || []);
/******/
/******/ 		// run deferred modules when all chunks ready
/******/ 		return checkDeferredModules();
/******/ 	};
/******/ 	function checkDeferredModules() {
/******/ 		var result;
/******/ 		for(var i = 0; i < deferredModules.length; i++) {
/******/ 			var deferredModule = deferredModules[i];
/******/ 			var fulfilled = true;
/******/ 			for(var j = 1; j < deferredModule.length; j++) {
/******/ 				var depId = deferredModule[j];
/******/ 				if(installedChunks[depId] !== 0) fulfilled = false;
/******/ 			}
/******/ 			if(fulfilled) {
/******/ 				deferredModules.splice(i--, 1);
/******/ 				result = __webpack_require__(__webpack_require__.s = deferredModule[0]);
/******/ 			}
/******/ 		}
/******/
/******/ 		return result;
/******/ 	}
/******/
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// object to store loaded and loading chunks
/******/ 	// undefined = chunk not loaded, null = chunk preloaded/prefetched
/******/ 	// Promise = chunk loading, 0 = chunk loaded
/******/ 	var installedChunks = {
/******/ 		"index": 0
/******/ 	};
/******/
/******/ 	var deferredModules = [];
/******/
/******/ 	// script path function
/******/ 	function jsonpScriptSrc(chunkId) {
/******/ 		return __webpack_require__.p + "static/js/" + ({"pages-cooperation-account~pages-cooperation-cooperation~pages-index-index~pages-index-setting~pages-~b580bc51":"pages-cooperation-account~pages-cooperation-cooperation~pages-index-index~pages-index-setting~pages-~b580bc51","pages-cooperation-account~pages-cooperation-cooperation~pages-index-index~pages-poi-choselocation~pa~8c4ace84":"pages-cooperation-account~pages-cooperation-cooperation~pages-index-index~pages-poi-choselocation~pa~8c4ace84","pages-cooperation-account~pages-cooperation-cooperation~pages-index-setting~pages-login-index~pages-~c12d7713":"pages-cooperation-account~pages-cooperation-cooperation~pages-index-setting~pages-login-index~pages-~c12d7713","pages-cooperation-account":"pages-cooperation-account","pages-cooperation-cooperation~pages-index-index~pages-index-setting~pages-poi-create~pages-poi-detai~9783d7c8":"pages-cooperation-cooperation~pages-index-index~pages-index-setting~pages-poi-create~pages-poi-detai~9783d7c8","pages-cooperation-cooperation~pages-index-index~pages-poi-create~pages-poi-detail~pages-poi-edit~pag~456f07b9":"pages-cooperation-cooperation~pages-index-index~pages-poi-create~pages-poi-detail~pages-poi-edit~pag~456f07b9","pages-cooperation-cooperation~pages-poi-create~pages-poi-edit":"pages-cooperation-cooperation~pages-poi-create~pages-poi-edit","pages-cooperation-cooperation":"pages-cooperation-cooperation","pages-poi-create~pages-poi-detail~pages-poi-poi":"pages-poi-create~pages-poi-detail~pages-poi-poi","pages-poi-create":"pages-poi-create","pages-poi-edit":"pages-poi-edit","pages-index-index~pages-poi-detail~pages-poi-sndetail":"pages-index-index~pages-poi-detail~pages-poi-sndetail","pages-index-index":"pages-index-index","pages-poi-detail":"pages-poi-detail","pages-poi-poi":"pages-poi-poi","pages-poi-choselocation":"pages-poi-choselocation","pages-poi-choselocationApp":"pages-poi-choselocationApp","pages-login-index":"pages-login-index","pages-index-setting":"pages-index-setting","pages-poi-sndetail":"pages-poi-sndetail"}[chunkId]||chunkId) + ".js"
/******/ 	}
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,"""
    },
    {
        "url": "https://test-enter-h5.powerbank.mykeeta.com/static/js/chunk-vendors.js",
        "content": """(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["chunk-vendors"],{

/***/ "+2oP":
/*!********************************************************!*\\
  !*** ./node_modules/core-js/modules/es.array.slice.js ***!
  \\********************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var $ = __webpack_require__(/*! ../internals/export */ "I+eb");
var isArray = __webpack_require__(/*! ../internals/is-array */ "6LWA");
var isConstructor = __webpack_require__(/*! ../internals/is-constructor */ "aO6C");
var isObject = __webpack_require__(/*! ../internals/is-object */ "hh1v");
var toAbsoluteIndex = __webpack_require__(/*! ../internals/to-absolute-index */ "I8vh");
var lengthOfArrayLike = __webpack_require__(/*! ../internals/length-of-array-like */ "B/qT");
var toIndexedObject = __webpack_require__(/*! ../internals/to-indexed-object */ "/GqU");
var createProperty = __webpack_require__(/*! ../internals/create-property */ "hBjN");
var wellKnownSymbol = __webpack_require__(/*! ../internals/well-known-symbol */ "tiKp");
var arrayMethodHasSpeciesSupport = __webpack_require__(/*! ../internals/array-method-has-species-support */ "Hd5f");
var nativeSlice = __webpack_require__(/*! ../internals/array-slice */ "82ph");

var HAS_SPECIES_SUPPORT = arrayMethodHasSpeciesSupport('slice');

var SPECIES = wellKnownSymbol('species');
var $Array = Array;
var max = Math.max;

// `Array.prototype.slice` method
// https://tc39.es/ecma262/#sec-array.prototype.slice
// fallback for not array-like ES3 strings and DOM objects
$({ target: 'Array', proto: true, forced: !HAS_SPECIES_SUPPORT }, {
  slice: function slice(start, end) {
    var O = toIndexedObject(this);
    var length = lengthOfArrayLike(O);
    var k = toAbsoluteIndex(start, length);
    var fin = toAbsoluteIndex(end === undefined ? length : end, length);
    // inline `ArraySpeciesCreate` for usage native `Array#slice` where it's possible
    var Constructor, result, n;
    if (isArray(O)) {
      Constructor = O.constructor;
      // cross-realm fallback
      if (isConstructor(Constructor) && (Constructor === $Array || isArray(Constructor.prototype))) {
        Constructor = undefined;
      } else if (isObject(Constructor)) {
        Constructor = Constructor[SPECIES];
        if (Constructor === null) Constructor = undefined;
      }
      if (Constructor === $Array || Constructor === undefined) {
        return nativeSlice(O, k, fin);
      }
    }
    result = new (Constructor === undefined ? $Array : Constructor)(max(fin - k, 0));
    for (n = 0; k < fin; k++, n++) if (k in O) createProperty(result, n, O[k]);
    result.length = n;
    return result;
  }
});


/***/ }),

/***/ "+M1K":
/*!***************************************************************!*\\
  !*** ./node_modules/core-js/internals/to-positive-integer.js ***!
  \\***************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var toIntegerOrInfinity = __webpack_require__(/*! ../internals/to-integer-or-infinity */ "WSbT");

var $RangeError = RangeError;

module.exports = function (it) {
  var result = toIntegerOrInfinity(it);
  if (result < 0) throw $RangeError("The argument can't be less than 0");
  return result;
};


/***/ }),

/***/ "+MnM":
/*!******************************************************************!*\\
  !*** ./node_modules/core-js/modules/es.reflect.to-string-tag.js ***!
  \\******************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var $ = __webpack_require__(/*! ../internals/export */ "I+eb");
var global = __webpack_require__(/*! ../internals/global */ "2oRo");
var setToStringTag = __webpack_require__(/*! ../internals/set-to-string-tag */ "1E5z");

$({ global: true }, { Reflect: {} });

// Reflect[@@toStringTag] property
// https://tc39.es/ecma262/#sec-reflect-@@tostringtag
setToStringTag(global.Reflect, 'Reflect', true);


/***/ }),

/***/ "/BHB":
/*!******************************************************************************************************!*\\
  !*** ./node_modules/@vue/babel-preset-app/node_modules/@babel/runtime/helpers/esm/defineProperty.js ***!
  \\******************************************************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = _defineProperty;
__webpack_require__(/*! core-js/modules/es.object.define-property.js */ "eoL8");
function _defineProperty(obj, key, value) {
  if (key in obj) {
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }
  return obj;
}

/***/ }),

/***/ "/G"""
    }
]

# 合并所有资源的分析结果
final_result = {
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

# 分析每个资源
for resource in resources:
    analysis = analyze_security(resource["content"], resource["url"])
    # 合并结果
    for key in final_result:
        if isinstance(final_result[key], list):
            final_result[key].extend(analysis[key])
        else:
            final_result[key] = analysis[key]

# 去重
for key in ["apis", "sensitive", "fingerprints", "maybe_vulns", "riskyScripts", "riskyApis"]:
    seen = set()
    unique_list = []
    for item in final_result[key]:
        item_str = json.dumps(item, sort_keys=True)
        if item_str not in seen:
            seen.add(item_str)
            unique_list.append(item)
    final_result[key] = unique_list

for key in ["ip", "ip_port", "domain", "path", "incomplete_path", "url", "mail", "sfz", "mobile", "jwt", "algorithm", "source_map", "static"]:
    final_result[key] = list(set(final_result[key]))

# 输出JSON
print(json.dumps(final_result, ensure_ascii=False, indent=2))
