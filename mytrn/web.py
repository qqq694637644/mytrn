"""A/B loopback Web UI: validated JSON config, status, and A-side proxy probe."""

from __future__ import annotations

import hmac
import json
import logging
import time

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp_socks import ProxyConnector

from .config import A_MKCP_DEFAULTS, load_json, save_json, validate

LOG = logging.getLogger("mytrn.web")
HTML = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mytrn · Xray 反向上网</title><style>
body{font:15px/1.6 system-ui,"Microsoft YaHei",sans-serif;max-width:920px;margin:30px auto;padding:0 18px;background:#f4f6f9;color:#17243a}
main{background:white;border:1px solid #dde5ef;border-radius:14px;padding:24px}
textarea{width:100%;box-sizing:border-box;min-height:420px;font:13px/1.5 Consolas,monospace;padding:12px;border:1px solid #ccd6e3;border-radius:8px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;background:#f0f4f8;border-radius:8px;font:13px/1.5 Consolas,monospace}
input{font:inherit;padding:9px;max-width:100%;width:350px;border:1px solid #bdc9d6;border-radius:6px}
input[type=number]{width:145px;box-sizing:border-box}
input[type=checkbox]{width:auto}
button{padding:9px 14px;margin:8px 8px 8px 0;background:#1f507a;color:white;border:0;border-radius:7px;cursor:pointer}
.cf-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px 20px;margin:14px 0}
.cf-grid label{display:flex;flex-direction:column;gap:4px}
.cf-grid input{box-sizing:border-box;width:100%}
.mkcp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:14px 20px;margin:14px 0}
.mkcp-grid label{display:flex;flex-direction:column;gap:4px}
.mkcp-grid label.checkbox{flex-direction:row;align-items:center}
small{color:#566478}h1{margin-bottom:0}
</style></head><body><main><h1>mytrn</h1><small>A 本地 SOCKS5 → Xray reverse/mKCP → B 境外互联网</small>
<p>Web 管理 token（来自 <code>python -m mytrn init</code>，保存在当前浏览器）：</p>
<input id="token" type="password" autocomplete="off"><button id="refresh">读取状态与配置</button>
<button id="probe">从 A 验证外网出口</button>
<h3>运行状态</h3><pre id="status">请输入 token 并读取</pre>
<section id="cf-panel" hidden>
<h3>控制面：CF CDN / VLESS（A 自有 Xray）</h3>
<p><small>Python 经 A Xray 的 10909 本地控制 SOCKS5，使用 VLESS + TLS + WebSocket 到现有 CF CDN 节点。v2rayN 只负责把本机上网流量交给 10808，不参与控制请求。以下参数请从当前已能使用的 CF/VLESS 节点照实填写；控制 HTTP 的目标是 B x-ui Go 服务。</small></p>
<div class="cf-grid">
<label>CF 节点地址（CDN 域名 / IP）<input id="control_cf_address" placeholder="你的 CF CDN 入口地址"></label>
<label>CF 节点端口（通常 443）<input id="control_cf_port" type="number" min="1" max="65535"></label>
<label>CF 节点 VLESS UUID（不是 MyTRN UUID）<input id="control_cf_uuid" placeholder="现有 VLESS 26417 节点 UUID"></label>
<label>TLS SNI<input id="control_cf_server_name" placeholder="CF 证书对应的 SNI"></label>
<label>WebSocket Host<input id="control_cf_ws_host" placeholder="现有节点 WS Host"></label>
<label>WebSocket Path<input id="control_cf_ws_path" placeholder="/你的实际路径"></label>
<label>B 控制 HTTP 主机/IP<input id="control_host" placeholder="B 的 HTTP 控制地址"></label>
<label>B 控制 HTTP 端口<input id="control_port" type="number" min="1" max="65535"></label>
<label>A 控制专用本地 SOCKS5 端口<input id="control_proxy_port" type="number" min="1" max="65535"></label>
</div>
<button id="cf-save">保存控制面配置</button>
<p><small>保存后按提示重启 Python Agent，A Xray 会自动生成控制出站并做配置校验。没有填好节点时控制面不发出直连请求，也不回退 v2rayN。修改不涉及 B 现有 CF/Caddy/VLESS 配置。</small></p>
</section>
<section id="mkcp-panel" hidden>
<h3>A 端 mKCP 传输参数</h3>
<p><small>当前 A Xray 入站默认 MTU=1200，其余使用 Xray 26.3.27 默认值。调参只重启 A 的 Xray 子进程，STUN/UDP 39999 网关不断开；B 在 x-ui 的 MyTRN 设置中单独调整。B/A 的 MTU 请保持兼容。</small></p>
<div class="mkcp-grid">
<label>MTU（字节）<input id="mkcp_mtu" type="number" min="576" max="1460" step="1"></label>
<label>TTI（毫秒）<input id="mkcp_tti" type="number" min="10" max="1000" step="1"></label>
<label>上行容量（MB/s）<input id="mkcp_uplink_capacity" type="number" min="1" max="1000" step="1"></label>
<label>下行容量（MB/s）<input id="mkcp_downlink_capacity" type="number" min="1" max="1000" step="1"></label>
<label>读缓冲（MB）<input id="mkcp_read_buffer_size" type="number" min="1" max="256" step="1"></label>
<label>写缓冲（MB）<input id="mkcp_write_buffer_size" type="number" min="1" max="256" step="1"></label>
<label class="checkbox"><input id="mkcp_congestion" type="checkbox">启用拥塞控制</label>
</div>
<button id="mkcp-save">保存并应用 A 的 mKCP</button><button id="mkcp-reset">恢复原有参数</button>
<p><small>readBufferSize 在当前 Xray 版本中虽支持配置，但实际读取窗口没有使用该值。header、seed 已被移除，不提供这些无效选项。</small></p>
</section>
<h3>配置（JSON）</h3><p><small>只编辑 mytrn 参数，不直接编辑 Xray 内核 JSON。仅修改 A 的 mKCP 参数时自动应用，控制面等其他配置保存后仍需重启 Python Agent；B MyTRN 使用同一 control_token 和 vless_uuid，CF 节点另用它自己的 VLESS UUID。</small></p>
<textarea id="config" spellcheck="false"></textarea><button id="save">校验并保存</button>
<pre id="message"></pre>
</main><script>
const $=(id)=>document.getElementById(id);$('token').value=localStorage.getItem('mytrn.admin')||'';
const cfKeys=['control_cf_address','control_cf_port','control_cf_uuid','control_cf_server_name',
              'control_cf_ws_host','control_cf_ws_path','control_host','control_port','control_proxy_port'];
function showCf(config){$('cf-panel').hidden=config.role!=='a';if(config.role!=='a')return;
for(const key of cfKeys)$(key).value=config[key]===undefined?'':config[key];}
function getCf(){const data={};for(const key of cfKeys){const raw=$(key).value.trim();
if(['control_cf_port','control_port','control_proxy_port'].includes(key)){
if(!/^\d+$/.test(raw))throw Error(key+' 必须是整数端口');data[key]=Number(raw);
}else data[key]=raw;}return data;}
const mkcpKeys=['mkcp_mtu','mkcp_tti','mkcp_uplink_capacity','mkcp_downlink_capacity','mkcp_read_buffer_size','mkcp_write_buffer_size','mkcp_congestion'];
const mkcpDefaults={mkcp_mtu:1200,mkcp_tti:50,mkcp_uplink_capacity:5,mkcp_downlink_capacity:20,mkcp_read_buffer_size:2,mkcp_write_buffer_size:2,mkcp_congestion:false};
function showMkcp(config){$('mkcp-panel').hidden=config.role!=='a';if(config.role!=='a')return;
for(const key of mkcpKeys){const value=config[key]===undefined?mkcpDefaults[key]:config[key];
if(key==='mkcp_congestion')$(key).checked=value;else $(key).value=value;}}
function getMkcp(){const values={};for(const key of mkcpKeys){if(key==='mkcp_congestion'){values[key]=$(key).checked;continue;}
const raw=$(key).value;if(!/^\d+$/.test(raw))throw Error(key+' 必须是整数');values[key]=Number(raw);}return values;}
async function api(path,method='GET',value){localStorage.setItem('mytrn.admin',$('token').value);
const opts={method,headers:{'X-Admin-Token':$('token').value,'Content-Type':'application/json'}};
if(value!==undefined)opts.body=JSON.stringify(value);
const resp=await fetch(path,opts),result=await resp.json();if(!resp.ok)throw Error(result.error||String(resp.status));return result;}
$('refresh').onclick=async()=>{try{$('status').textContent=JSON.stringify(await api('/api/status'),null,2);
$('config').value=JSON.stringify(await api('/api/config'),null,2);showMkcp(JSON.parse($('config').value));
showCf(JSON.parse($('config').value));$('message').textContent='读取成功';}catch(e){$('message').textContent=e.message;}};
$('save').onclick=async()=>{try{const obj=JSON.parse($('config').value);
$('message').textContent=(await api('/api/config','POST',obj)).message;showMkcp(obj);showCf(obj);}catch(e){$('message').textContent=e.message;}};
$('cf-save').onclick=async()=>{try{const config=await api('/api/config');
if(config.role!=='a')throw Error('控制面配置仅用于 A Python');Object.assign(config,getCf());
const result=await api('/api/config','POST',config);$('config').value=JSON.stringify(config,null,2);
$('message').textContent=result.message;showCf(config);}catch(e){$('message').textContent=e.message;}};
$('mkcp-save').onclick=async()=>{try{const config=await api('/api/config');
if(config.role!=='a')throw Error('mKCP 表单仅用于 A Python');Object.assign(config,getMkcp());
const result=await api('/api/config','POST',config);$('config').value=JSON.stringify(config,null,2);
$('message').textContent=result.message;showMkcp(config);}catch(e){$('message').textContent=e.message;}};
$('mkcp-reset').onclick=()=>showMkcp({role:'a',...mkcpDefaults});
$('probe').onclick=async()=>{try{$('message').textContent='正在通过 A SOCKS5 检测...';
$('message').textContent=JSON.stringify(await api('/api/probe','POST',{}),null,2);}catch(e){$('message').textContent=e.message;}};
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
            if self.agent.role == "a" and changed <= A_MKCP_DEFAULTS.keys():
                # The 3-second Xray supervisor sees the new desired config,
                # validates it, and restarts only its own child Xray. Keep
                # Python STUN, UDP 39999, control and Web UI continuously up.
                self.agent.config = new_config
                if changed:
                    self.agent.proxy_probe = None
                return web.json_response({"ok": True, "message":
                    "mKCP 已保存，A 的 Xray 将自动校验并应用（通常约 3 秒）；Python/UDP 39999 无需重启。"})
            self.agent.restart_required = True
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response({"ok": True, "message": "保存成功。请重启 agent，配置将自动生成 Xray 内核配置。"})

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
        app.router.add_post("/api/probe", self.probe)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, cfg["web_bind"], cfg["web_port"]).start()
        LOG.info("%s Web UI http://%s:%s", self.agent.role.upper(), cfg["web_bind"], cfg["web_port"])

    async def close(self):
        if self.runner:
            await self.runner.cleanup()
            self.runner = None
