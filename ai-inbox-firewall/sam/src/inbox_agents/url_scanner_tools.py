"""
URL Security Scanner tools for SAM agents.

These tools check URLs for malware, phishing, and other security threats
using the VirusTotal API (free tier: 500 requests/day).

Get your free API key at: https://www.virustotal.com/gui/join-us
"""

import logging
import base64
import asyncio
from typing import Any, Dict, Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)


async def scan_url_virustotal(
    url: str,
    tool_context: Optional[Any] = None,
    tool_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Scan a URL for malware, phishing, and security threats using VirusTotal.

    Args:
        url: The URL to scan (e.g., "https://example.com/page").

    Returns:
        A dictionary with security analysis results from 70+ antivirus engines.
    """
    log_id = f"[URLScanner:virustotal:{url[:50]}]"
    log.debug(f"{log_id} Starting scan")

    # Get API key from tool_config
    api_key = None
    if tool_config:
        api_key = tool_config.get("virustotal_api_key")

    if not api_key:
        log.error(f"{log_id} No VirusTotal API key configured")
        return {
            "status": "error",
            "message": "VirusTotal API key not configured. Get a free key at https://www.virustotal.com/gui/join-us and set VIRUSTOTAL_API_KEY in .env",
        }

    # Validate URL format
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {
                "status": "error",
                "message": f"Invalid URL format: {url}. Must include scheme (http/https).",
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not parse URL: {str(e)}",
        }

    try:
        import aiohttp

        headers = {"x-apikey": api_key}
        
        # Step 1: Submit URL for scanning
        log.debug(f"{log_id} Submitting URL to VirusTotal")
        async with aiohttp.ClientSession() as session:
            # Submit the URL
            async with session.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
            ) as response:
                if response.status == 401:
                    return {
                        "status": "error",
                        "message": "Invalid VirusTotal API key. Check your VIRUSTOTAL_API_KEY.",
                    }
                if response.status != 200:
                    error_text = await response.text()
                    return {
                        "status": "error",
                        "message": f"VirusTotal API error: {response.status} - {error_text}",
                    }
                
                submit_data = await response.json()
                analysis_id = submit_data.get("data", {}).get("id")

            # Step 2: Wait for analysis to complete and get results
            # Use URL ID for direct lookup (faster than waiting for analysis)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            
            # Brief wait for scan to process
            await asyncio.sleep(2)
            
            log.debug(f"{log_id} Fetching analysis results")
            async with session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            ) as response:
                if response.status == 404:
                    # URL not in database yet, check analysis status
                    await asyncio.sleep(5)
                    async with session.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                    ) as analysis_response:
                        result_data = await analysis_response.json()
                        stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
                elif response.status == 200:
                    result_data = await response.json()
                    stats = result_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                else:
                    error_text = await response.text()
                    return {
                        "status": "error", 
                        "message": f"Failed to get results: {response.status} - {error_text}",
                    }

        # Parse results
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        # Determine threat level
        if malicious > 0:
            threat_level = "HIGH"
            verdict = "DANGEROUS"
        elif suspicious > 0:
            threat_level = "MEDIUM"
            verdict = "SUSPICIOUS"
        else:
            threat_level = "LOW"
            verdict = "CLEAN"

        log.info(f"{log_id} Scan complete: {verdict} ({malicious} malicious, {suspicious} suspicious)")

        return {
            "status": "success",
            "url": url,
            "verdict": verdict,
            "threat_level": threat_level,
            "summary": f"{malicious} engines detected this URL as malicious, {suspicious} as suspicious, {harmless} as harmless",
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines,
            },
            "recommendation": _get_recommendation(verdict, malicious, suspicious),
            "virustotal_link": f"https://www.virustotal.com/gui/url/{url_id}",
        }

    except ImportError:
        log.error(f"{log_id} aiohttp not installed")
        return {
            "status": "error",
            "message": "aiohttp package not installed. Add 'aiohttp' to dependencies.",
        }
    except Exception as e:
        log.error(f"{log_id} Unexpected error: {e}", exc_info=True)
        return {
            "status": "error",
            "message": f"Scan failed: {str(e)}",
        }


async def analyze_url_structure(
    url: str,
    tool_context: Optional[Any] = None,
    tool_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Analyze a URL's structure for common phishing and malware indicators.
    This is a quick local check that doesn't require an API key.

    Args:
        url: The URL to analyze.

    Returns:
        A dictionary with structural risk indicators.
    """
    log_id = f"[URLScanner:analyze_structure:{url[:50]}]"
    log.debug(f"{log_id} Analyzing URL structure")

    try:
        parsed = urlparse(url)
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not parse URL: {str(e)}",
        }

    warnings = []
    risk_score = 0

    # Check for IP address instead of domain
    domain = parsed.netloc.split(":")[0]  # Remove port if present
    if _is_ip_address(domain):
        warnings.append("URL uses IP address instead of domain name (common in phishing)")
        risk_score += 30

    # Check for suspicious TLDs
    suspicious_tlds = [".xyz", ".top", ".work", ".click", ".link", ".tk", ".ml", ".ga", ".cf", ".gq"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        warnings.append(f"Uses suspicious top-level domain")
        risk_score += 20

    # Check for excessive subdomains
    subdomain_count = domain.count(".")
    if subdomain_count > 3:
        warnings.append(f"Excessive subdomains ({subdomain_count} levels) - possible domain spoofing")
        risk_score += 15

    # Check for brand name spoofing patterns
    spoofed_brands = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "bank", "secure", "login", "account", "verify"]
    domain_lower = domain.lower()
    for brand in spoofed_brands:
        if brand in domain_lower and not domain_lower.endswith(f"{brand}.com"):
            warnings.append(f"Contains '{brand}' but is not the official domain")
            risk_score += 25
            break

    # Check for URL encoding tricks
    if "%00" in url or "%2e" in url.lower() or "%2f" in url.lower():
        warnings.append("Contains encoded characters that may hide true destination")
        risk_score += 20

    # Check for @ symbol (can hide real domain)
    if "@" in parsed.netloc:
        warnings.append("Contains @ symbol which can hide the real destination")
        risk_score += 35

    # Check for very long URLs
    if len(url) > 200:
        warnings.append(f"Unusually long URL ({len(url)} characters)")
        risk_score += 10

    # Check for suspicious paths
    suspicious_paths = ["/wp-admin", "/wp-includes", "/.well-known", "/cgi-bin", "/phpmyadmin"]
    if any(path in parsed.path.lower() for path in suspicious_paths):
        warnings.append("Contains path commonly targeted by attackers")
        risk_score += 10

    # Check HTTPS
    if parsed.scheme != "https":
        warnings.append("Not using HTTPS (unencrypted connection)")
        risk_score += 15

    # Determine risk level
    if risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    log.info(f"{log_id} Analysis complete: risk_score={risk_score}, warnings={len(warnings)}")

    return {
        "status": "success",
        "url": url,
        "domain": domain,
        "scheme": parsed.scheme,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "warnings": warnings,
        "warning_count": len(warnings),
        "note": "This is a heuristic analysis. Use scan_url_virustotal for comprehensive threat detection.",
    }


def _is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address."""
    import re
    # IPv4 pattern
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # IPv6 pattern (simplified)
    ipv6_pattern = r"^\[?[0-9a-fA-F:]+\]?$"
    return bool(re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain))


def _get_recommendation(verdict: str, malicious: int, suspicious: int) -> str:
    """Generate a security recommendation based on scan results."""
    if verdict == "DANGEROUS":
        return f"🚨 DO NOT VISIT THIS URL. {malicious} security vendors flagged it as malicious. This URL may contain malware, phishing, or other threats."
    elif verdict == "SUSPICIOUS":
        return f"⚠️ PROCEED WITH CAUTION. {suspicious} security vendors flagged this URL as suspicious. Verify the source before visiting."
    else:
        return "✅ No threats detected by security vendors. However, always exercise caution with unfamiliar URLs."
