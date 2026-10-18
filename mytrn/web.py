"""A/B loopback Web UI: validated config, clear restart state and proxy checks."""

from __future__ import annotations

import hmac
import json
import logging
import time

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp_socks import ProxyConnector

from .config import A_MKCP_DEFAULTS, load_json, save_json, validate
from .control import check_control_route

LOG = logging.getLogger("mytrn.web")

# Fully standalone local UI. Never import CDN assets into an administrator page.
HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MyTRN · A 端管理</title>
<style>
:root{color-scheme:light;--bg:#f3f6fa;--card:#fff;--ink:#182a40;--muted:#52647a;--line:#dbe3ed;--blue:#185785;--warn:#875200;--err:#a11f2f}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,"Microsoft YaHei",sans-serif}
main{max-width:1080px;margin:24px auto;padding:0 16px 40px}
h1{font-size:25px;margin:0 0 4px}h2{font-size:19px;margin:0 0 10px}h3{font-size:16px}
p{margin:8px 0 14px}.subtitle,.hint{color:var(--muted);font-size:13px}.hint{line-height:1.65}
section.panel,.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px;margin-top:18px;box-shadow:0 2px 7px #182a4010}
[hidden]{display:none!important}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px 20px;margin:16px 0}
.field{display:flex;flex-direction:column;gap:5px;min-width:0}
.field>span{font-size:13px;color:#344c66;overflow-wrap:anywhere}
.field.full{grid-column:1/-1}
input,select,textarea{font:inherit;color:var(--ink);border:1px solid #bfcbda;border-radius:7px;padding:9px 11px;background:#fff;min-width:0;max-width:100%;width:100%}
input:focus,select:focus,textarea:focus{outline:2px solid #80b8e9;outline-offset:1px}
input[type=checkbox]{width:auto;margin:0 8px 0 0}
input.mono,textarea{font-family:Consolas,"Courier New",monospace;font-size:13px}
.checkbox{display:flex;flex-direction:row;align-items:center;gap:2px;margin-top:8px}
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:16px}
button{font:inherit;background:var(--blue);border:1px solid var(--blue);border-radius:7px;color:white;cursor:pointer;padding:9px 14px}
button.secondary{background:white;color:var(--blue)}button:disabled{opacity:.55;cursor:wait}
.auth{display:grid;grid-template-columns:minmax(200px,1fr) auto auto;gap:12px;align-items:end}
.notice{background:#f0f6fd;color:#244665;border-left:3px solid #4a91ca;padding:10px 12px;border-radius:5px;margin:12px 0;font-size:13px}
.notice.warning{background:#fff6e7;color:var(--warn);border-color:#d08c27}
.notice.error{background:#fff0f1;color:var(--err);border-color:#c73a4a}
#message{white-space:pre-wrap;overflow-wrap:anywhere;color:#244665;background:#f0f6fd;border-radius:8px;padding:12px;margin-top:16px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fa;border-radius:8px;padding:12px;font:12px/1.6 Consolas,monospace}
textarea{min-height:340px;line-height:1.5;resize:vertical}
details{margin-top:12px}summary{cursor:pointer;color:var(--blue);font-weight:600}
.status-pill{display:inline-block;background:#eff4fb;border-radius:5px;padding:4px 9px;font-size:13px;margin-right:6px}
@media(max-width:700px){main{margin:12px auto;padding:0 10px 24px}.panel,section.panel{padding:16px}.grid{grid-template-columns:minmax(0,1fr)}.auth{grid-template-columns:minmax(0,1fr)}.field.full{grid-column:auto}button{max-width:100%}}
</style></head><body><main>
<header><h1>MyTRN · A 端管理</h1><p class="subtitle">Python 管理一个 Xray：控制面走 CF/XHTTP，用户数据面走 mKCP；v2rayN 只负责本机流量入口。</p></header>
<section class="panel">
  <h2>管理与运行状态</h2>
  <div class="auth"><label class="field"><span>本地 Web 管理 Token</span><input id="token" type="password" autocomplete="off" placeholder="请输入 admin_token"></label>
    <button id="refresh">读取当前配置</button><button id="probe" class="secondary">检测 B 出口</button></div>
  <p id="runtime-summary" class="hint">输入管理 Token 后读取状态。</p>
  <div id="restart-hint" class="notice warning" hidden>配置已经保存，但尚未应用到正在运行的 Python Agent。请重启 A Agent，再检测控制链路。</div>
  <details><summary>查看运行状态明细</summary><pre id="status">尚未加载</pre></details>
</section>
<section id="cf-panel" class="panel" hidden>
  <h2>控制面 · CF CDN / VLESS + XHTTP</h2>
  <p class="hint">下方参数必须与 v2rayN <strong>已经能连通的 XHTTP 节点</strong>一致。特别注意：XHTTP 不是 WebSocket；你当前节点模式是 packet-up、TLS 指纹 chrome、ALPN h3。A Python 使用独立的本地 SOCKS5，不经过 v2rayN。</p>
  <div class="grid">
    <label class="field"><span>CDN 入口地址（address）</span><input id="control_cf_address" spellcheck="false" placeholder="CDN 域名或 IP"></label>
    <label class="field"><span>CDN 入口端口</span><input id="control_cf_port" type="number" min="1" max="65535"></label>
    <label class="field full"><span>CF 节点 VLESS UUID（不是 MyTRN UUID）</span><input id="control_cf_uuid" class="mono" spellcheck="false" autocomplete="off" placeholder="现有节点用户 ID"></label>
    <label class="field"><span>TLS SNI</span><input id="control_cf_server_name" spellcheck="false" placeholder="现有节点 SNI"></label>
    <label class="field"><span>XHTTP Host</span><input id="control_cf_xhttp_host" spellcheck="false" placeholder="现有节点 Host"></label>
    <label class="field"><span>XHTTP Path</span><input id="control_cf_xhttp_path" spellcheck="false" placeholder="/现有节点路径"></label>
    <label class="field"><span>XHTTP 模式</span><select id="control_cf_xhttp_mode"><option value="packet-up">packet-up（当前节点）</option><option value="stream-up">stream-up</option><option value="stream-one">stream-one</option></select></label>
    <label class="field"><span>TLS Fingerprint</span><select id="control_cf_fingerprint"><option value="chrome">chrome（当前节点）</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="edge">edge</option></select></label>
    <label class="field"><span>TLS ALPN</span><select id="control_cf_alpn"><option value="h3">h3（当前节点，使用 UDP）</option><option value="h2">h2（使用 TCP）</option></select></label>
    <label class="field"><span>B 的 Go 控制 HTTP 主机 / IP</span><input id="control_host" spellcheck="false" placeholder="B 实际 HTTP 监听地址"></label>
    <label class="field"><span>B 的 Go 控制 HTTP 端口</span><input id="control_port" type="number" min="1" max="65535"></label>
    <label class="field"><span>A 控制专用本地 SOCKS5 端口</span><input id="control_proxy_port" type="number" min="1" max="65535"></label>
  </div>
  <div class="notice">本机控制入口默认 <b>127.0.0.1:10909</b> → Xray CF/XHTTP 出站 → B Go HTTP。用户数据入口仍是 <b>10808</b>，STUN/UDP 数据网关仍是 <b>39999 → 40001</b>。</div>
  <div class="actions"><button id="cf-save">保存控制面配置</button><button id="cf-check" class="secondary">检测 CF → B 控制链路（只读）</button></div>
  <p class="hint">控制面修改后必须重启 A Python Agent 才会应用。检测使用<strong>当前正在运行</strong>的 Xray 配置，仅检查 B Go HTTP 可达性，不修改 A/B 映射。</p>
</section>
<section id="mkcp-panel" class="panel" hidden>
  <h2>A 端 mKCP 数据面参数</h2>
  <p class="hint">A Xray 在回环 UDP 40001 处理 VLESS/mKCP/TLS，Python UDP 39999 做 STUN 和数据报转发。下面只修改 mKCP；保存后由 Python 校验并重启 A 的 Xray 子进程，不重启 UDP 网关。</p>
  <div class="grid">
    <label class="field"><span>MTU（字节）</span><input id="mkcp_mtu" type="number" min="576" max="1460" step="1"></label>
    <label class="field"><span>TTI（毫秒）</span><input id="mkcp_tti" type="number" min="10" max="1000" step="1"></label>
    <label class="field"><span>上行容量（MB/s）</span><input id="mkcp_uplink_capacity" type="number" min="1" max="1000" step="1"></label>
    <label class="field"><span>下行容量（MB/s）</span><input id="mkcp_downlink_capacity" type="number" min="1" max="1000" step="1"></label>
    <label class="field"><span>读缓冲（MB）</span><input id="mkcp_read_buffer_size" type="number" min="1" max="256" step="1"></label>
    <label class="field"><span>写缓冲（MB）</span><input id="mkcp_write_buffer_size" type="number" min="1" max="256" step="1"></label>
    <label class="checkbox field full"><input id="mkcp_congestion" type="checkbox"><span>启用拥塞控制</span></label>
  </div>
  <div class="actions"><button id="mkcp-save">保存并应用 A 的 mKCP</button><button id="mkcp-reset" class="secondary">填写原有默认值</button></div>
  <p class="hint">“填写原有默认值”只修改输入框，必须点击保存才会写入。readBufferSize 在当前 Xray 版本中不参与读取窗口计算。</p>
</section>
<section class="panel"><details id="advanced"><summary>高级 · JSON 配置（包含凭据）</summary>
  <p class="hint">这是 mytrn 配置，不是 Xray 内核 JSON。建议优先使用上面两个表单；高级编辑完成后校验并保存。这里包含 UUID 和 Token，请勿公开分享。</p>
  <textarea id="config" spellcheck="false" aria-label="高级 JSON 配置"></textarea>
  <div class="actions"><button id="save">校验并保存 JSON</button></div>
</details><div id="message" role="status" aria-live="polite">未执行操作</div></section>
</main><script>
const $=(id)=>document.getElementById(id);
$('token').value=localStorage.getItem('mytrn.admin')||'';
const cfKeys=['control_cf_address','control_cf_port','control_cf_uuid','control_cf_server_name',
  'control_cf_xhttp_host','control_cf_xhttp_path','control_cf_xhttp_mode',
  'control_cf_fingerprint','control_cf_alpn','control_host','control_port','control_proxy_port'];
const numericCfKeys=['control_cf_port','control_port','control_proxy_port'];
const mkcpKeys=['mkcp_mtu','mkcp_tti','mkcp_uplink_capacity','mkcp_downlink_capacity',
  'mkcp_read_buffer_size','mkcp_write_buffer_size','mkcp_congestion'];
const mkcpDefaults={mkcp_mtu:1200,mkcp_tti:50,mkcp_uplink_capacity:5,mkcp_downlink_capacity:20,
  mkcp_read_buffer_size:2,mkcp_write_buffer_size:2,mkcp_congestion:false};
function showCf(config){$('cf-panel').hidden=config.role!=='a';if(config.role!=='a')return;
  for(const key of cfKeys)$(key).value=config[key]===undefined?'':config[key];}
function showMkcp(config){$('mkcp-panel').hidden=config.role!=='a';if(config.role!=='a')return;
  for(const key of mkcpKeys){const value=config[key]===undefined?mkcpDefaults[key]:config[key];
    if(key==='mkcp_congestion')$(key).checked=value;else $(key).value=value;}}
function getCf(){const result={};for(const key of cfKeys){const raw=$(key).value.trim();
  if(numericCfKeys.includes(key)){if(!/^\d+$/.test(raw))throw Error(key+' 必须是整数端口');result[key]=Number(raw);}
  else result[key]=raw;}return result;}
function getMkcp(){const result={};for(const key of mkcpKeys){if(key==='mkcp_congestion'){result[key]=$(key).checked;continue;}
  const raw=$(key).value.trim();if(!/^\d+$/.test(raw))throw Error(key+' 必须是整数');result[key]=Number(raw);}return result;}
function message(text,isError=false){$('message').textContent=text;$('message').style.color=isError?'#a11f2f':'#244665';}
async function api(path,method='GET',value){localStorage.setItem('mytrn.admin',$('token').value);
  const opts={method,cache:'no-store',headers:{'X-Admin-Token':$('token').value}};
  if(value!==undefined){opts.body=JSON.stringify(value);opts.headers['Content-Type']='application/json';}
  const response=await fetch(path,opts);
  let result;try{result=await response.json();}catch{throw Error('服务器未返回有效 JSON（HTTP '+response.status+'）');}
  if(!response.ok)throw Error(result.error||'HTTP '+response.status);return result;}
function renderStatus(status){$('status').textContent=JSON.stringify(status,null,2);
  $('restart-hint').hidden=!status.restart_required;
  const xray=status.xray||{};
  const items=[xray.running?'Xray 运行中':'Xray 未运行',
    status.control_configured?'CF 控制节点已配置':'CF 控制节点未配置',
    status.control_last_registration?'B 已收到过映射':'尚无成功的控制注册'];
  $('runtime-summary').textContent=items.join(' · ');
}
async function reload(){const config=await api('/api/config');
  $('config').value=JSON.stringify(config,null,2);showCf(config);showMkcp(config);
  renderStatus(await api('/api/status'));return config;}
async function operation(button,work){button.disabled=true;try{return await work();}catch(err){message(err.message,true);}
  finally{button.disabled=false;}}
$('refresh').onclick=()=>operation($('refresh'),async()=>{await reload();message('已读取当前保存的配置和运行状态');});
$('save').onclick=()=>operation($('save'),async()=>{const config=JSON.parse($('config').value);
  const result=await api('/api/config','POST',config);await reload();message(result.message);});
$('cf-save').onclick=()=>operation($('cf-save'),async()=>{const config=await api('/api/config');
  if(config.role!=='a')throw Error('CF 控制面设置仅用于 A');Object.assign(config,getCf());
  const result=await api('/api/config','POST',config);await reload();message(result.message);});
$('mkcp-save').onclick=()=>operation($('mkcp-save'),async()=>{const config=await api('/api/config');
  if(config.role!=='a')throw Error('mKCP 设置仅用于 A');Object.assign(config,getMkcp());
  const result=await api('/api/config','POST',config);await reload();message(result.message);});
$('mkcp-reset').onclick=()=>showMkcp({role:'a',...mkcpDefaults});
$('cf-check').onclick=()=>operation($('cf-check'),async()=>{
  message('正在通过 A 自有 Xray 的 CF/XHTTP 出站检测 B Go 控制 API（不会更改 endpoint）...');
  const result=await api('/api/control/check','POST',{});message(result.message);});
$('probe').onclick=()=>operation($('probe'),async()=>{
  message('正在通过 A 数据 SOCKS5 → mKCP → B freedom 检测互联网出口...');
  const result=await api('/api/probe','POST',{});message(JSON.stringify(result,null,2));});
</script></body></html>"""


class WebUI:
    def __init__(self, agent):
        self.agent = agent
        self.runner = None

    def authorized(self, request):
        return hmac.compare_digest(request.headers.get("X-Admin-Token", ""), self.agent.config["admin_token"])

    async def index(self, _):
        return web.Response(text=HTML, content_type="text/html", headers={"Cache-Control": "no-store",
                            "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
                            "X-Content-Type-Options": "nosniff"})

    async def status(self, request):
        if not self.authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        return web.json_response(self.agent.status(), headers={"Cache-Control": "no-store"})

    async def config(self, request):
        if not self.authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        config = load_json(self.agent.path)
        validate(config, self.agent.role)
        return web.json_response(config, headers={"Cache-Control": "no-store"})

    async def save(self, request):
        if not self.authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            new_config = await request.json()
            validate(new_config, self.agent.role)
            changed = {key for key in new_config if new_config[key] != self.agent.config.get(key)}
            save_json(self.agent.path, new_config)
            if self.agent.role == "a" and changed <= A_MKCP_DEFAULTS.keys() and not self.agent.restart_required:
                # The Xray supervisor applies ONLY mKCP changes while the
                # Python STUN/UDP socket continues using its current config.
                self.agent.config = new_config
                if changed:
                    self.agent.proxy_probe = None
                return web.json_response({"ok": True, "message":
                    "mKCP 已保存，A 的 Xray 将自动校验并应用；Python/UDP 39999 无需重启。"})
            if changed:
                self.agent.restart_required = True
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response({"ok": True, "message":
            "已保存。需要重启 A Python Agent 才能应用新的 CF 控制面/其他设置。" if self.agent.restart_required
            else "配置没有变化，无需重启。"})

    async def check_control(self, request):
        if not self.authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        if self.agent.role != "a":
            return web.json_response({"error": "control check only available on A"}, status=400)
        if self.agent.restart_required:
            return web.json_response({"error": "控制面配置有待应用的变更，请先重启 A Python Agent"}, status=409)
        if not self.agent.xray or not self.agent.xray.status()["running"]:
            return web.json_response({"error": "A Xray 未运行，请先检查内核启动状态"}, status=503)
        try:
            result = await check_control_route(self.agent.config)
            return web.json_response(result, headers={"Cache-Control": "no-store"})
        except Exception as exc:
            LOG.warning("A CF/XHTTP control route check failed: %s", exc)
            return web.json_response({"error": f"控制通道不可达：{type(exc).__name__}: {exc}。请核对 XHTTP/packet-up、TLS Fingerprint、ALPN h3 和 B HTTP 监听地址。"}, status=502)

    async def probe(self, request):
        if not self.authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        if self.agent.role != "a":
            return web.json_response({"error": "proxy probe only available on A"}, status=400)
        # ProxyConnector does remote DNS via SOCKS5; never fall back to direct.
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{self.agent.config['socks_port']}", rdns=True)
        try:
            async with ClientSession(connector=connector, timeout=ClientTimeout(total=18), trust_env=False) as client:
                async with client.get("https://api.ipify.org?format=json") as response:
                    response.raise_for_status()
                    if response.content_length and response.content_length > 1024:
                        raise ValueError("probe response too large")
                    result = await response.json()
                    ip = result["ip"]
                    if not isinstance(ip, str) or len(ip) > 50:
                        raise ValueError("invalid exit IP")
                    self.agent.proxy_probe = {"ok": True, "egress_ip": ip, "timestamp": time.time()}
                    return web.json_response(self.agent.proxy_probe)
        except Exception as exc:
            self.agent.proxy_probe = {"ok": False, "error": str(exc), "timestamp": time.time()}
            LOG.warning("A actual SOCKS5→B→Internet probe failed: %s", exc)
            return web.json_response(self.agent.proxy_probe, status=502)

    async def start(self):
        cfg = self.agent.config
        app = web.Application(client_max_size=64 * 1024)
        app.router.add_get("/", self.index)
        app.router.add_get("/api/status", self.status)
        app.router.add_get("/api/config", self.config)
        app.router.add_post("/api/config", self.save)
        app.router.add_post("/api/control/check", self.check_control)
        app.router.add_post("/api/probe", self.probe)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, cfg["web_bind"], cfg["web_port"]).start()
        LOG.info("%s Web UI http://%s:%s", self.agent.role.upper(), cfg["web_bind"], cfg["web_port"])

    async def close(self):
        if self.runner:
            await self.runner.cleanup()
            self.runner = None
