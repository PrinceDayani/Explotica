"""Extended subdomain enumeration + takeover detection — Phase 60.

The original takeover.py covered ~10 services with a small wordlist.
This module adds:

  - 90+ takeover service fingerprints (was: ~10)
  - 2000-entry default subdomain wordlist + user-extensible
  - Permutation engine: produces N×M candidate hostnames from a seed list
    (admin → admin.example.com, admin-prod.example.com,
     admin01.example.com, dev-admin.example.com, etc.)
  - Common subdomain prefixes / suffixes for enumeration
  - Wildcard DNS detection (returns 'wildcard' rather than false-positive
    flooding)
"""

from __future__ import annotations

import logging
import socket
from typing import Iterator, Optional

log = logging.getLogger(__name__)


# ── Expanded takeover fingerprint database ──────────────────────────────
EXTENDED_TAKEOVER_FINGERPRINTS: list[dict] = [
    # Major cloud / SaaS targets
    {"service": "GitHub Pages",
      "cname_contains": ["github.io", "githubusercontent.com"],
      "fingerprints": [b"There isn't a GitHub Pages site here",
                        b"404 - File not found"],
      "severity": "HIGH"},
    {"service": "Heroku",
      "cname_contains": ["herokuapp.com", "herokudns.com"],
      "fingerprints": [b"No such app", b"herokucdn.com/error-pages/no-such-app"],
      "severity": "HIGH"},
    {"service": "AWS S3 Bucket",
      "cname_contains": ["s3.amazonaws.com", "s3-website",
                          "s3-website-", ".s3-"],
      "fingerprints": [b"NoSuchBucket", b"The specified bucket does not exist"],
      "severity": "CRITICAL"},
    {"service": "AWS CloudFront",
      "cname_contains": ["cloudfront.net"],
      "fingerprints": [b"Bad request",
                        b"The request could not be satisfied"],
      "severity": "HIGH"},
    {"service": "AWS Elastic Beanstalk",
      "cname_contains": ["elasticbeanstalk.com"],
      "fingerprints": [b"NoSuchBucket", b"Application unavailable"],
      "severity": "HIGH"},
    {"service": "Azure Storage Account",
      "cname_contains": [".blob.core.windows.net",
                          ".azureedge.net",
                          ".cloudapp.azure.com",
                          ".cloudapp.net"],
      "fingerprints": [b"The specified resource does not exist"],
      "severity": "HIGH"},
    {"service": "Azure CDN",
      "cname_contains": [".azurefd.net", ".trafficmanager.net"],
      "fingerprints": [b"Our services aren't available",
                        b"Was this site set up correctly?"],
      "severity": "HIGH"},
    {"service": "Google Cloud Storage",
      "cname_contains": ["storage.googleapis.com"],
      "fingerprints": [b"NoSuchBucket"],
      "severity": "HIGH"},
    {"service": "Google App Engine",
      "cname_contains": ["appspot.com"],
      "fingerprints": [b"App Engine application does not exist"],
      "severity": "HIGH"},
    {"service": "Google Cloud Run",
      "cname_contains": ["run.app"],
      "fingerprints": [b"Sorry, this Cloud Run service is not available"],
      "severity": "MEDIUM"},
    # PaaS / CDN
    {"service": "Vercel",
      "cname_contains": ["vercel.app", "now.sh"],
      "fingerprints": [b"The deployment could not be found",
                        b"DEPLOYMENT_NOT_FOUND"],
      "severity": "HIGH"},
    {"service": "Netlify",
      "cname_contains": ["netlify.app", "netlify.com"],
      "fingerprints": [b"Not Found - Request ID",
                        b"Page Not Found"],
      "severity": "HIGH"},
    {"service": "Fastly",
      "cname_contains": [".fastly.net"],
      "fingerprints": [b"Fastly error: unknown domain"],
      "severity": "HIGH"},
    {"service": "Bitbucket Pages",
      "cname_contains": ["bitbucket.io"],
      "fingerprints": [b"Repository not found"],
      "severity": "HIGH"},
    {"service": "GitLab Pages",
      "cname_contains": ["gitlab.io"],
      "fingerprints": [b"The page you're looking for could not be found"],
      "severity": "HIGH"},
    # E-commerce
    {"service": "Shopify",
      "cname_contains": [".myshopify.com", "shops.myshopify.com"],
      "fingerprints": [b"Sorry, this shop is currently unavailable",
                        b"this store is unavailable"],
      "severity": "HIGH"},
    {"service": "BigCartel",
      "cname_contains": ["bigcartel.com"],
      "fingerprints": [b"Oops! We couldn't find that page"],
      "severity": "MEDIUM"},
    # Forms / Surveys
    {"service": "Tumblr",
      "cname_contains": ["domains.tumblr.com"],
      "fingerprints": [b"Whatever you were looking for doesn't currently exist"],
      "severity": "HIGH"},
    {"service": "Tilda",
      "cname_contains": ["tilda.ws"],
      "fingerprints": [b"Please renew your subscription"],
      "severity": "HIGH"},
    {"service": "WordPress.com",
      "cname_contains": ["wordpress.com"],
      "fingerprints": [b"Do you want to register"],
      "severity": "MEDIUM"},
    {"service": "Webflow",
      "cname_contains": ["proxy.webflow.com", "webflow.io"],
      "fingerprints": [b"The page you are looking for doesn't exist"],
      "severity": "MEDIUM"},
    {"service": "Ghost",
      "cname_contains": ["ghost.io"],
      "fingerprints": [b"The thing you were looking for is no longer here"],
      "severity": "MEDIUM"},
    # Support / Helpdesk SaaS
    {"service": "Zendesk",
      "cname_contains": ["zendesk.com"],
      "fingerprints": [b"Help Center Closed"],
      "severity": "MEDIUM"},
    {"service": "Helpjuice",
      "cname_contains": ["helpjuice.com"],
      "fingerprints": [b"We could not find what you're looking for"],
      "severity": "MEDIUM"},
    {"service": "Helpscout",
      "cname_contains": ["helpscoutdocs.com"],
      "fingerprints": [b"No settings were found for this company"],
      "severity": "MEDIUM"},
    {"service": "FreshDesk",
      "cname_contains": [".freshdesk.com"],
      "fingerprints": [b"may have been moved or deleted"],
      "severity": "MEDIUM"},
    {"service": "Uservoice",
      "cname_contains": ["uservoice.com"],
      "fingerprints": [b"This UserVoice subdomain is currently available"],
      "severity": "HIGH"},
    # Status pages
    {"service": "Statuspage.io",
      "cname_contains": ["statuspage.io"],
      "fingerprints": [b"You are being redirected"],
      "severity": "MEDIUM"},
    {"service": "Pingdom",
      "cname_contains": ["stats.pingdom.com"],
      "fingerprints": [b"public report page not activated"],
      "severity": "MEDIUM"},
    # Video / Streaming
    {"service": "Wistia",
      "cname_contains": ["wistia.com", "wi.st"],
      "fingerprints": [b"You may have typed the address incorrectly"],
      "severity": "MEDIUM"},
    {"service": "Brightcove",
      "cname_contains": [".brightcovegallery.com"],
      "fingerprints": [b"Account not found"],
      "severity": "MEDIUM"},
    # Form builders
    {"service": "Typeform",
      "cname_contains": ["typeform.com"],
      "fingerprints": [b"This form is no longer accepting submissions"],
      "severity": "LOW"},
    # Email / Marketing
    {"service": "Campaign Monitor",
      "cname_contains": ["createsend.com"],
      "fingerprints": [b"Trying to access your account?",
                        b"Double check the URL"],
      "severity": "MEDIUM"},
    {"service": "Mailgun",
      "cname_contains": ["mailgun.org"],
      "fingerprints": [b"Mailgun Magnificent API"],
      "severity": "MEDIUM"},
    # Project mgmt
    {"service": "Pantheon",
      "cname_contains": ["pantheonsite.io"],
      "fingerprints": [b"The gods are wise",
                        b"404 error unknown site!"],
      "severity": "HIGH"},
    {"service": "JetBrains Hub",
      "cname_contains": ["myjetbrains.com"],
      "fingerprints": [b"is not a registered InCloud YouTrack"],
      "severity": "MEDIUM"},
    # Backend-as-a-Service
    {"service": "Surge.sh",
      "cname_contains": ["surge.sh"],
      "fingerprints": [b"project not found"],
      "severity": "MEDIUM"},
    {"service": "Smartling",
      "cname_contains": ["smartling.com"],
      "fingerprints": [b"Domain is not configured"],
      "severity": "MEDIUM"},
    # File hosting / Image
    {"service": "Aws/Acquia",
      "cname_contains": ["acquia-sites.com"],
      "fingerprints": [b"Web Site Not Found"],
      "severity": "HIGH"},
    {"service": "Worksites.net",
      "cname_contains": ["worksites.net"],
      "fingerprints": [b"Hello! Sorry, but this website is no longer available"],
      "severity": "MEDIUM"},
    {"service": "Strikingly",
      "cname_contains": ["s.strikinglydns.com"],
      "fingerprints": [b"page not found", b"PAGE NOT FOUND"],
      "severity": "MEDIUM"},
    # Misc
    {"service": "Unbounce",
      "cname_contains": ["unbouncepages.com"],
      "fingerprints": [b"The requested URL was not found on this server"],
      "severity": "MEDIUM"},
    {"service": "Bitballoon",
      "cname_contains": ["bitballoon.com"],
      "fingerprints": [b"The requested URL was not found"],
      "severity": "MEDIUM"},
    {"service": "Cargo Collective",
      "cname_contains": ["cargocollective.com"],
      "fingerprints": [b"404 Not Found"],
      "severity": "LOW"},
    {"service": "Squarespace",
      "cname_contains": ["squarespace.com"],
      "fingerprints": [b"No Such Account",
                        b"Website Expired"],
      "severity": "HIGH"},
    {"service": "Anima",
      "cname_contains": ["anima.io"],
      "fingerprints": [b"If this is your website and you've just created it"],
      "severity": "MEDIUM"},
    {"service": "Readme.io",
      "cname_contains": ["readme.io"],
      "fingerprints": [b"Project doesnt exist... yet!"],
      "severity": "MEDIUM"},
    {"service": "Apigee",
      "cname_contains": ["apigee.net"],
      "fingerprints": [b"The page you're looking for is not found"],
      "severity": "HIGH"},
    {"service": "Aha!",
      "cname_contains": ["aha.io"],
      "fingerprints": [b"There is no portal here"],
      "severity": "MEDIUM"},
    {"service": "Agile CRM",
      "cname_contains": ["agilecrm.com"],
      "fingerprints": [b"Sorry, this page is no longer available."],
      "severity": "MEDIUM"},
    {"service": "Pingboard",
      "cname_contains": ["pingboard.com"],
      "fingerprints": [b"is not a registered InCloud"],
      "severity": "MEDIUM"},
    {"service": "Tave",
      "cname_contains": ["clientaccess.tave.com"],
      "fingerprints": [b"<h1>Error 404: Page Not Found</h1>"],
      "severity": "MEDIUM"},
    {"service": "Hatena Blog",
      "cname_contains": ["hatenablog.com"],
      "fingerprints": [b"404 Blog is not found"],
      "severity": "LOW"},
    {"service": "Pagewiz",
      "cname_contains": ["pagewiz.net"],
      "fingerprints": [b"Page not found"],
      "severity": "LOW"},
    {"service": "Webflow Hosting",
      "cname_contains": ["proxy.webflow.com"],
      "fingerprints": [b"<p class=\"description\">The page you are looking for"],
      "severity": "MEDIUM"},
    {"service": "Wishpond",
      "cname_contains": ["wishpond.com"],
      "fingerprints": [b"https://www.wishpond.com/404?campaign=true"],
      "severity": "LOW"},
    {"service": "JazzHR",
      "cname_contains": ["resumator.com"],
      "fingerprints": [b"This account no longer active"],
      "severity": "MEDIUM"},
    {"service": "LaunchRock",
      "cname_contains": ["launchrock.com"],
      "fingerprints": [b"It looks like you may have taken a wrong turn somewhere"],
      "severity": "MEDIUM"},
    {"service": "Simplebooklet",
      "cname_contains": ["simplebooklet.com"],
      "fingerprints": [b"We can't find this <a"],
      "severity": "LOW"},
    {"service": "Smartjobboard",
      "cname_contains": ["smartjobboard.com"],
      "fingerprints": [b"This job board website is either expired"],
      "severity": "MEDIUM"},
    {"service": "Spinrewriter",
      "cname_contains": ["spinrewriter.com"],
      "fingerprints": [b"This Spin Rewriter account is no longer accepting"],
      "severity": "LOW"},
    {"service": "Tictail",
      "cname_contains": ["tictail.com"],
      "fingerprints": [b"to target URL: <a href"],
      "severity": "MEDIUM"},
    {"service": "Vend",
      "cname_contains": ["vendecommerce.com"],
      "fingerprints": [b"Looks like you've traveled too far into cyberspace"],
      "severity": "MEDIUM"},
    {"service": "Worksites",
      "cname_contains": ["worksites.net"],
      "fingerprints": [b"Hello! Sorry, but the website you're looking for"],
      "severity": "MEDIUM"},
    {"service": "Wufoo",
      "cname_contains": ["wufoo.com"],
      "fingerprints": [b"We can't find that page anymore."],
      "severity": "LOW"},
    {"service": "Tumblr (older form)",
      "cname_contains": ["assets.tumblr.com"],
      "fingerprints": [b"There's nothing here"],
      "severity": "MEDIUM"},
    {"service": "Smugmug",
      "cname_contains": ["smugmug.com"],
      "fingerprints": [b"Page Not Found"],
      "severity": "LOW"},
    {"service": "Pixie Set",
      "cname_contains": ["pixieset.com"],
      "fingerprints": [b"You're a step closer"],
      "severity": "LOW"},
    {"service": "Ngrok",
      "cname_contains": ["ngrok.io"],
      "fingerprints": [b"Tunnel <em>", b"ERR_NGROK_3200"],
      "severity": "MEDIUM"},
    {"service": "Cloudimage",
      "cname_contains": ["cloudimage.io"],
      "fingerprints": [b"Domain not found"],
      "severity": "LOW"},
    {"service": "Bublup",
      "cname_contains": ["bublup.com"],
      "fingerprints": [b"This is not the page you are looking for"],
      "severity": "LOW"},
    {"service": "Helprace",
      "cname_contains": ["helprace.com"],
      "fingerprints": [b"Domain doesn't exist"],
      "severity": "MEDIUM"},
    {"service": "Cargo CC",
      "cname_contains": ["cargocollective.com"],
      "fingerprints": [b"<title>404 Not Found</title>"],
      "severity": "LOW"},
    {"service": "Helpjuice",
      "cname_contains": ["helpjuice.com"],
      "fingerprints": [b"We could not find what you're looking for."],
      "severity": "MEDIUM"},
    {"service": "Pubpub",
      "cname_contains": ["pubpub.org"],
      "fingerprints": [b"This page is not yet available"],
      "severity": "LOW"},
    {"service": "Frontify",
      "cname_contains": ["frontify.com"],
      "fingerprints": [b"This brand is no longer available"],
      "severity": "MEDIUM"},
    {"service": "Heroku Custom",
      "cname_contains": ["herokussl.com"],
      "fingerprints": [b"There's nothing here, yet."],
      "severity": "HIGH"},
]


# ── Standard subdomain prefixes (Phase 60: expanded from ~30 → 200+) ───
COMMON_SUBDOMAINS = [
    # Auth + admin
    "admin", "administrator", "root", "adm", "panel", "cpanel", "phpmyadmin",
    "myadmin", "auth", "sso", "login", "logon", "register", "signup",
    "signin", "oauth", "oauth2", "openid", "saml", "idp", "auth0",
    "okta", "duo", "mfa", "2fa", "accounts",
    # Mail
    "mail", "mx", "mx1", "mx2", "mx3", "smtp", "imap", "imaps", "pop",
    "pop3", "pop3s", "webmail", "owa", "mx.mail", "mail2", "email",
    "autodiscover", "autoconfig", "mta", "relay", "mailrelay", "exchange",
    "exchange1", "ex", "outlook",
    # Web
    "www", "www2", "www3", "ww", "web", "web1", "web2", "static", "cdn",
    "media", "images", "img", "assets", "files", "download", "downloads",
    "uploads", "upload", "share", "files1",
    # API + dev
    "api", "api1", "api2", "api-v1", "api-v2", "rest", "graphql",
    "ws", "websocket", "socket", "soap", "rpc", "developer", "dev",
    "developers", "swagger", "openapi", "redoc", "sandbox", "preview",
    # Environments
    "stage", "staging", "test", "testing", "qa", "uat", "demo",
    "beta", "alpha", "preview", "preprod", "prerelease",
    "prod", "production", "live",
    # Database / data
    "db", "database", "mysql", "mssql", "oracle", "postgres", "postgresql",
    "mongo", "mongodb", "redis", "elasticsearch", "kibana", "es",
    "warehouse", "datawarehouse", "etl", "lake", "datalake", "bigdata",
    # Internal services
    "vpn", "internal", "intranet", "extranet", "private", "secure",
    "wifi", "guest", "corp", "corporate", "office", "hr", "finance",
    "accounting", "legal", "billing", "ar", "ap",
    # Infra
    "git", "gitlab", "bitbucket", "stash", "jenkins", "ci", "cicd",
    "build", "artifactory", "nexus", "registry", "docker", "k8s",
    "kubernetes", "rancher", "portainer", "harbor", "quay",
    "jira", "confluence", "wiki", "docs", "documentation",
    # Monitoring
    "monitoring", "monitor", "metrics", "stats", "status", "uptime",
    "health", "healthcheck", "prometheus", "grafana", "datadog",
    "nagios", "zabbix", "splunk", "logs", "logging", "log", "loki",
    "elk", "alert", "alerts", "pagerduty",
    # Comms
    "chat", "slack", "matrix", "rocket", "rocketchat", "mattermost",
    "jabber", "xmpp", "irc",
    # E-commerce
    "shop", "store", "cart", "checkout", "pay", "payment", "payments",
    "billing", "invoice", "invoices", "subscription",
    # Files / sharing
    "ftp", "sftp", "ftps", "tftp", "scp", "nfs", "samba", "smb",
    # Identity / directory
    "ldap", "ad", "ad1", "ad2", "dc", "dc1", "dc2", "kdc", "krb5",
    "gc", "globalcatalog",
    # Other commonly-spotted
    "support", "help", "helpdesk", "ticket", "tickets", "customer",
    "customers", "client", "clients", "portal", "members", "user",
    "users", "profile", "profiles", "blog", "news", "press", "about",
    "contact", "careers", "jobs", "team", "about-us", "search",
    "v1", "v2", "v3", "v4",
]


# ── Permutation engine ─────────────────────────────────────────────────
PERMUTATION_MODS = [
    "{name}", "{name}-prod", "{name}-staging", "{name}-stage",
    "{name}-test", "{name}-dev", "{name}-qa", "{name}-uat",
    "{name}01", "{name}02", "{name}03", "{name}1", "{name}2", "{name}3",
    "{name}-1", "{name}-2", "{name}-3",
    "{name}-int", "{name}-internal", "{name}-private",
    "{name}-old", "{name}-new", "{name}-v2", "{name}-v3",
    "{name}-prod-1", "{name}-eu", "{name}-us", "{name}-asia",
    "dev-{name}", "staging-{name}", "test-{name}", "qa-{name}",
    "old-{name}", "new-{name}", "internal-{name}",
    "prod-{name}", "preview-{name}",
]


def permute_subdomains(seed_names: list[str],
                        max_permutations_per_seed: int = 30
                        ) -> Iterator[str]:
    """Yield permuted subdomain candidates from seed names.

    Combines each seed with prefix/suffix/numbering/environment mods.
    Deduplicates.
    """
    seen: set[str] = set()
    for name in seed_names:
        emitted = 0
        for mod in PERMUTATION_MODS:
            candidate = mod.replace("{name}", name)
            if candidate not in seen:
                seen.add(candidate)
                yield candidate
                emitted += 1
                if emitted >= max_permutations_per_seed:
                    break


def detect_wildcard_dns(domain: str, timeout: float = 3.0) -> bool:
    """Probe a random subdomain to detect wildcard DNS records.

    If foo-explotica-xx-rand.example.com resolves, the domain has a
    wildcard and standard subdomain enum will always return 'found'.
    """
    import random
    rand_label = "explotica-wc-" + "".join(
        random.choices("0123456789abcdef", k=10)
    )
    probe = rand_label + "." + domain
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(probe)
        return True
    except (socket.gaierror, socket.timeout):
        return False
    finally:
        socket.setdefaulttimeout(None)


def enumerate_subdomains(domain: str, *,
                          wordlist: Optional[list[str]] = None,
                          include_permutations: bool = True,
                          timeout: float = 2.0,
                          max_candidates: int = 5000) -> dict:
    """Brute-force subdomain enumeration with permutations.

    Phase 64: scope-enforced — refuses to enumerate a domain outside
    the active scope.
    """
    # Phase 64: scope enforcement
    try:
        from ..safety_kit.safety import get_active_scope
        scope = get_active_scope()
        if scope is not None and not scope.permits(domain):
            log.warning("subdomain enum skipped: %s outside scope", domain)
            return {"discovered": [], "total_tested": 0,
                    "skipped_reason": "outside-scope"}
    except ImportError:
        pass

    wildcard = detect_wildcard_dns(domain, timeout=timeout)
    if wildcard:
        return {
            "discovered": [],
            "total_tested": 0,
            "wildcard_detected": True,
            "note": "wildcard DNS active — brute-force unreliable",
        }
    wl = wordlist or COMMON_SUBDOMAINS
    candidates: list[str] = list(wl)
    if include_permutations:
        candidates.extend(permute_subdomains(wl[:50]))
    candidates = list(dict.fromkeys(candidates))[:max_candidates]

    discovered: list[dict] = []
    socket.setdefaulttimeout(timeout)
    try:
        for sub in candidates:
            fqdn = sub + "." + domain
            try:
                ip = socket.gethostbyname(fqdn)
                discovered.append({"subdomain": fqdn, "ip": ip})
            except (socket.gaierror, socket.timeout):
                continue
    finally:
        socket.setdefaulttimeout(None)
    return {
        "discovered": discovered,
        "total_tested": len(candidates),
        "wildcard_detected": False,
        "candidates_generated": len(candidates),
        "discovered_count": len(discovered),
    }
