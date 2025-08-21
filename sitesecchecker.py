import streamlit as st
import httpx
import socket
import ssl
import idna
import json
import re
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone

############################
# ---------- UI -----------#
############################
st.set_page_config(
    page_title="Site Security Checker",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Minimal aesthetic polish via custom CSS
st.markdown(
    """
    <style>
      .main {padding-top: 1.5rem;}
      .title {font-size: 2.1rem; font-weight: 800;}
      .subtitle {color: #667085;}
      .card {background:#ffffff; border:1px solid #eef0f3; border-radius:16px; padding:16px; box-shadow:0 4px 14px rgba(0,0,0,0.06);} 
      .good {background:#ECFDF3; color:#027A48; border:1px solid #ABEFC6;}
      .warn {background:#FFF7ED; color:#B54708; border:1px solid #FED7AA;}
      .bad  {background:#FEF2F2; color:#B42318; border:1px solid #FECDCA;}
      .muted {color:#475467}
      .metric {font-weight:700; font-size:1.1rem}
      .pill {display:inline-block; padding:4px 10px; border-radius:999px; border:1px solid #e6e8eb; margin-right:6px; margin-bottom:6px;}
      code {background:#f3f4f6; padding:2px 6px; border-radius:6px}
      .section h3 {margin-bottom:0.2rem}

      /* Force neutral metrics to black in LIGHT theme (beats Streamlit theme tokens) */
      html[data-theme="light"] div[data-testid="stMarkdownContainer"] 
        .card:not(.good):not(.warn):not(.bad) .metric {
        color:#000 !important;
        -webkit-text-fill-color:#000 !important;
        opacity:1 !important;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

############################
# ------ Utilities --------#
############################

def normalize_url(u: str) -> str:
    u = u.strip()
    if not u:
        return u
    # Add scheme if missing
    parsed = urlparse(u if re.match(r"^\w+://", u) else f"https://{u}")
    # IDNA encode host (punycode) but leave shown URL human-friendly
    try:
        host = parsed.hostname
        host_idna = idna.encode(host).decode("ascii") if host else host
    except Exception:
        host_idna = parsed.hostname
    rebuilt = parsed._replace(netloc=(host_idna + (f":{parsed.port}" if parsed.port else "")))
    return urlunparse(rebuilt)


def http_head(url: str, timeout=10.0) -> httpx.Response:
    """Try HEAD, fall back to GET with stream=True and no body read."""
    client = httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": "SiteSecurityChecker/1.0"})
    try:
        r = client.head(url)
        if r.status_code >= 400 or r.request.method != "HEAD":
            # Some servers disallow HEAD; try a lightweight GET
            r = client.get(url, headers={"Range": "bytes=0-0"})
        return r
    finally:
        client.close()


def fetch_homepage(url: str, timeout=15.0) -> httpx.Response:
    client = httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": "SiteSecurityChecker/1.0"})
    try:
        r = client.get(url)
        return r
    finally:
        client.close()


def get_redirect_chain(url: str, timeout=10.0):
    history = []
    with httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": "SiteSecurityChecker/1.0"}) as client:
        r = client.get(url)
        for h in r.history:
            history.append({
                "status": h.status_code,
                "url": str(h.url),
            })
        history.append({"status": r.status_code, "url": str(r.url)})
    return history


def resolve_dns(host: str):
    try:
        ip = socket.gethostbyname(host)
        return {"ip": ip}
    except Exception as e:
        return {"error": str(e)}


def get_server_cert(host: str, port: int = 443):
    info = {"ok": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
        # cert is a dict when binary_form=False
        info.update({
            "ok": True,
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "version": tls_version,
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
            "subjectAltName": cert.get("subjectAltName"),
        })
        # Expiry calculations
        try:
            exp = datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            info["days_to_expiry"] = (exp - now).days
        except Exception:
            pass
    except Exception as e:
        info["error"] = str(e)
    return info


def check_http_to_https_upgrade(host: str) -> dict:
    """Request http:// and see if it upgrades to https://"""
    try:
        with httpx.Client(follow_redirects=False, timeout=8.0) as c:
            r = c.get(f"http://{host}")
            loc = r.headers.get("location", "")
            return {
                "status": r.status_code,
                "upgrades": (r.is_redirect and loc.lower().startswith("https://")),
                "location": loc,
            }
    except Exception as e:
        return {"error": str(e)}


def analyze_security(url: str) -> dict:
    data = {"input": url, "normalized": None}
    url_n = normalize_url(url)
    data["normalized"] = url_n
    parsed = urlparse(url_n)
    host = parsed.hostname or ""

    # DNS
    dns = resolve_dns(host)
    data["dns"] = dns

    # Redirect chain & final URL
    try:
        chain = get_redirect_chain(url_n)
    except Exception as e:
        chain = [{"error": str(e)}]
    data["redirect_chain"] = chain
    final_url = chain[-1].get("url") if chain and "url" in chain[-1] else url_n
    data["final_url"] = final_url
    final_parsed = urlparse(final_url)

    # HEAD/Headers on final URL
    headers = {}
    status = None
    try:
        r_head = http_head(final_url)
        headers = {k.lower(): v for k, v in r_head.headers.items()}
        status = r_head.status_code
    except Exception as e:
        headers = {"error": str(e)}
    data["status_code"] = status
    data["headers"] = headers

    # Homepage content for mixed-content scan
    html_snippet = None
    try:
        r_page = fetch_homepage(final_url)
        html = r_page.text or ""
        html_snippet = html[:4000]
        http_refs = re.findall(r'http://[^"]+', html, flags=re.IGNORECASE)
    except Exception:
        http_refs = []
    data["mixed_content_http_links"] = list(sorted(set(http_refs)))[:50]
    data["html_snippet"] = html_snippet

    # SSL / TLS (only if https)
    cert = None
    tls_version = None
    if final_parsed.scheme == "https" and host:
        cert = get_server_cert(host)
        tls_version = cert.get("version") if cert else None
    data["certificate"] = cert

    # HSTS
    hsts = headers.get("strict-transport-security") if isinstance(headers, dict) else None
    data["hsts"] = hsts

    # HTTP -> HTTPS upgrade check
    upgrade = check_http_to_https_upgrade(host) if host else {"error": "no host"}
    data["http_to_https"] = upgrade

    # Cookie flags
    set_cookies = headers.get("set-cookie", "") if isinstance(headers, dict) else ""
    cookie_issues = []
    if set_cookies:
        # Check for Secure and HttpOnly flags and SameSite
        cookies = [c.strip() for c in set_cookies.split(", ") if "=" in c]
        for c in cookies[:30]:
            flags = c.split(";")
            flag_str = ";".join(flags[1:]).lower()
            name = flags[0].split("=")[0]
            if "secure" not in flag_str:
                cookie_issues.append(f"Cookie '{name}' missing Secure flag")
            if "httponly" not in flag_str:
                cookie_issues.append(f"Cookie '{name}' missing HttpOnly flag")
            if "samesite" not in flag_str:
                cookie_issues.append(f"Cookie '{name}' missing SameSite flag")
    data["cookie_issues"] = sorted(set(cookie_issues))

    # Security headers presence
    sec_headers = {
        "content-security-policy": None,
        "x-content-type-options": None,
        "x-frame-options": None,
        "referrer-policy": None,
        "permissions-policy": None,  # formerly Feature-Policy
        "strict-transport-security": None,
        "cross-origin-opener-policy": None,
        "cross-origin-resource-policy": None,
        "cross-origin-embedder-policy": None,
    }
    if isinstance(headers, dict):
        for k in list(sec_headers.keys()):
            sec_headers[k] = headers.get(k)
    data["security_headers"] = sec_headers

    # Quick heuristics / scoring
    score = 100
    findings = []

    # TLS checks
    if final_parsed.scheme != "https":
        findings.append(("error", "Site does not use HTTPS"))
        score -= 35
    else:
        if cert and not cert.get("ok"):
            findings.append(("error", f"Could not retrieve certificate: {cert.get('error','unknown')}"))
            score -= 20
        elif cert:
            dte = cert.get("days_to_expiry")
            if isinstance(dte, int):
                if dte < 0:
                    findings.append(("error", "TLS certificate is EXPIRED"))
                    score -= 40
                elif dte < 15:
                    findings.append(("warn", f"TLS certificate expires soon ({dte} days)") )
                    score -= 10
            if tls_version and not str(tls_version).startswith("TLS"):
                findings.append(("warn", f"Unrecognized TLS version: {tls_version}"))
                score -= 5

    # HSTS
    if not hsts:
        findings.append(("warn", "HSTS header not detected (Strict-Transport-Security)"))
        score -= 8

    # HTTP→HTTPS upgrade
    if isinstance(upgrade, dict) and upgrade.get("status") and not upgrade.get("upgrades"):
        findings.append(("warn", "HTTP does not upgrade to HTTPS"))
        score -= 6

    # Mixed content
    if data["mixed_content_http_links"]:
        findings.append(("warn", f"Page references {len(data['mixed_content_http_links'])} insecure (http://) resources"))
        score -= min(15, 2 * len(data["mixed_content_http_links"]))

    # Security headers quality
    sh = sec_headers
    must_have = [
        ("content-security-policy", "Consider adding a strict Content-Security-Policy"),
        ("x-content-type-options", "Add X-Content-Type-Options: nosniff"),
        ("x-frame-options", "Add X-Frame-Options to mitigate clickjacking"),
        ("referrer-policy", "Add a privacy-friendly Referrer-Policy (e.g., no-referrer)"),
        ("permissions-policy", "Define a minimal Permissions-Policy")
    ]
    for key, msg in must_have:
        if not sh.get(key):
            findings.append(("warn", f"Missing security header: {key}. {msg}"))
            score -= 3

    # Clamp score
    score = max(0, min(100, score))
    data["score"] = score
    data["findings"] = findings
    return data

############################
# --------- App ---------- #
############################
with st.sidebar:
    st.markdown("### ⚙️ Options")
    show_html = st.toggle("Include HTML snippet preview", value=False, help="Show up to ~4KB of the homepage HTML to eyeball issues.")
    st.markdown("---")
    st.markdown("**What we check:**\n\n- HTTPS / TLS version\n- Certificate issuer & expiry\n- HTTP→HTTPS upgrade\n- Security headers (CSP, HSTS, etc.)\n- Cookie flags (Secure, HttpOnly, SameSite)\n- Mixed-content (insecure http:// references)\n- Basic DNS/redirect overview\n\n*Note:* We do not query 3rd‑party blacklists or perform active vulnerability scans.")

url = st.text_input("Website URL", placeholder="https://example.com", help="We will follow redirects and analyze the final landing page.")

analyze = st.button("🔍 Analyze Security")

if analyze:
    if not url.strip():
        st.error("Please enter a website URL.")
    else:
        with st.spinner("Running checks…"):
            report = analyze_security(url)

        # Top summary row
        col1, col2, col3, col4 = st.columns([1,1,1,1])
        
        with col1:
            st.markdown("#### Overall Score")
            score = report.get("score", 0)
            badge_class = "good" if score >= 85 else ("warn" if score >= 60 else "bad")
            st.markdown(
                f"<div class='card {badge_class}'><div class='metric'>🔒 {score}/100</div><div class='muted'>Heuristic security hygiene</div></div>",
                unsafe_allow_html=True
            )
        
        with col2:
            st.markdown("#### Final URL")
            st.markdown(
                f"<div class='card'><code>{report.get('final_url','')}</code></div>",
                unsafe_allow_html=True
            )
        
        with col3:
            st.markdown("#### Status Code")
            st.markdown(
                f"<div class='card'><div class='metric' style='color:#000;-webkit-text-fill-color:#000;opacity:1'>{report.get('status_code','')}</div><div class='muted'>HTTP response</div></div>",
                unsafe_allow_html=True
            )
        
        with col4:
            st.markdown("#### DNS IP")
            ip = report.get("dns",{}).get("ip","—")
            st.markdown(
                f"<div class='card'><div class='metric' style='color:#000;-webkit-text-fill-color:#000;opacity:1'>📍 {ip}</div><div class='muted'>A record</div></div>",
                unsafe_allow_html=True
            )
        
        st.markdown("---")

        # TLS / Certificate
        st.markdown("### 🔐 TLS & Certificate")
        cert = report.get("certificate") or {}
        c1, c2, c3 = st.columns([1,1,1])
        with c1:
            st.markdown("**TLS Version**")
            st.code(str(cert.get("version", "n/a")))
            dte = cert.get("days_to_expiry")
            if dte is not None:
                st.caption(f"Days to expiry: {dte}")
        with c2:
            st.markdown("**Issuer**")
            st.write(cert.get("issuer", "n/a"))
        with c3:
            st.markdown("**Valid To**")
            st.code(cert.get("notAfter", "n/a"))

        # HSTS & Upgrade
        st.markdown("### 🔁 Transport Security")
        u1, u2 = st.columns([1,1])
        with u1:
            st.markdown("**HSTS (Strict-Transport-Security)**")
            hsts = report.get("hsts")
            st.code(hsts or "(not present)")
        with u2:
            st.markdown("**HTTP → HTTPS Upgrade**")
            up = report.get("http_to_https", {})
            if up.get("error"):
                st.error(up.get("error"))
            else:
                st.write(up)

        # Security Headers
        st.markdown("### 🧱 Security Headers")
        sh = report.get("security_headers", {})
        cols = st.columns(3)
        keys = list(sh.keys())
        for i, key in enumerate(keys):
            with cols[i % 3]:
                val = sh.get(key) or "(missing)"
                present = "good" if sh.get(key) else "bad"
                st.markdown(f"<div class='card {present}'><div class='metric'>{key}</div><div class='muted'>{val}</div></div>", unsafe_allow_html=True)

        # Cookies
        st.markdown("### 🍪 Cookies")
        issues = report.get("cookie_issues", [])
        if not issues:
            st.success("No obvious cookie flag issues detected.")
        else:
            for issue in issues:
                st.markdown(f"<span class='pill'>⚠️ {issue}</span>", unsafe_allow_html=True)

        # Mixed content
        st.markdown("### 🌐 Mixed Content")
        http_refs = report.get("mixed_content_http_links", [])
        if not http_refs:
            st.success("No insecure (http://) subresources spotted on the homepage.")
        else:
            st.warning(f"Found {len(http_refs)} insecure references (showing up to 50).")
            with st.expander("Show list"):
                for ref in http_refs:
                    st.code(ref)

        # Redirect chain
        st.markdown("### 🧭 Redirect Chain")
        with st.expander("View redirects"):
            for hop in report.get("redirect_chain", []):
                st.markdown(f"<div class='card'><b>{hop.get('status','')}</b> → <code>{hop.get('url','')}</code></div>", unsafe_allow_html=True)

        # HTML snippet (optional)
        if show_html and report.get("html_snippet"):
            st.markdown("### 🧩 HTML Snippet (first ~4KB)")
            st.code(report["html_snippet"])

        # Findings
        st.markdown("### 📌 Findings & Advice")
        for level, msg in report.get("findings", []):
            klass = "good" if level == "ok" else ("warn" if level == "warn" else "bad")
            icon = "✅" if level == "ok" else ("⚠️" if level == "warn" else "⛔")
            st.markdown(f"<div class='card {klass}'>{icon} {msg}</div>", unsafe_allow_html=True)

        # Download JSON
        st.markdown("### 📦 Export Report")
        fn = "security_report.json"
        st.download_button(
            label="Download JSON",
            data=json.dumps(report, indent=2),
            file_name=fn,
            mime="application/json",
        )

else:
    st.info("Enter a URL and click **Analyze Security** to get started.")

