"""A/B loopback Web UI: validated JSON config, status, and A-side proxy probe."""

from __future__ import annotations

import hmac
import json
import logging
import time

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp_socks import ProxyConnector

from .config import load_json, save_json, validate

LOG = logging.getLogger("mytrn.web")
HTML = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mytrn · Xray 反向上网</title><style>
body{font:15px/1.6 system-ui,"Microsoft YaHei",sans-serif;max-width:920px;margin:30px auto;padding:0 18px;background:#f4f6f9;color:#17243a}
main{background:white;border:1px solid #dde5ef;border-radius:14px;padding:24px}
textarea{width:100%;box-sizing:border-box;min-height:420px;font:13px/1.5 Consolas,monospace;padding:12px;border:1px solid #ccd6e3;border-radius:8px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;background:#f0f4f8;border-radius:8px;font:13px/1.5 Consolas,monospace}
input{font:inherit;padding:9px;max-width:100%;width:350px;border:1px solid #bdc9d6;border-radius:6px}
button{padding:9px 14px;margin:8px 8px 8px 0;background:#1f507a;color:white;border:0;border-radius:7px;cursor:pointer}
small{color:#566478}h1{margin-bottom:0}
</style></head><body><main><h1>mytrn</h1><small>A 本地 SOCKS5 → Xray reverse/mKCP → B 境外互联网</small>
<p>Web 管理 token（来自 <code>python -m mytrn init</code>，保存在当前浏览器）：</p>
<input id="token" type="password" autocomplete="off"><button id="refresh">读取状态与配置</button>
<button id="probe">从 A 验证外网出口</button>
<h3>运行状态</h3><pre id="status">请输入 token 并读取</pre>
<h3>配置（JSON）</h3><p><small>只编辑 mytrn 参数，不直接编辑 Xray 内核 JSON。保存成功后重启 agent 生效；B 必须使用与 A 相同的 control_token 和 vless_uuid。</small></p>
<textarea id="config" spellcheck="false"></textarea><button id="save">校验并保存</button>
<pre id="message"></pre>
</main><script>
const $=(id)=>document.getElementById(id);$('token').value=localStorage.getItem('mytrn.admin')||'';
async function api(path,method='GET',value){localStorage.setItem('mytrn.admin',$('token').value);
const opts={method,headers:{'X-Admin-Token':$('token').value,'Content-Type':'application/json'}};
if(value!==undefined)opts.body=JSON.stringify(value);
const resp=await fetch(path,opts),result=await resp.json();if(!resp.ok)throw Error(result.error||String(resp.status));return result;}
$('refresh').onclick=async()=>{try{$('status').textContent=JSON.stringify(await api('/api/status'),null,2);
$('config').value=JSON.stringify(await api('/api/config'),null,2);$('message').textContent='读取成功';}catch(e){$('message').textContent=e.message;}};
$('save').onclick=async()=>{try{const obj=JSON.parse($('config').value);
$('message').textContent=(await api('/api/config','POST',obj)).message;}catch(e){$('message').textContent=e.message;}};
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
        return web.json_response(load_json(self.agent.path), headers={"Cache-Control": "no-store"})

    async def save(self, request):
        if not self.authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            new_config = await request.json()
            validate(new_config, self.agent.role)
            save_json(self.agent.path, new_config)
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
