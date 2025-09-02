from flask import Flask, request, Response, render_template_string, redirect, session
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote, unquote, urlparse
import re
import json
import os
from http.cookies import SimpleCookie

app = Flask(__name__)
app.secret_key = 'proxy_browser_secret_key_change_in_production'  # Change this in production

# Load configuration
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"warning_sites": [], "warning_message": "", "warning_style": {}}

config = load_config()

# Cookie handling functions
def get_cookies_for_domain(domain):
    """Get stored cookies for a specific domain"""
    if 'cookies' not in session:
        session['cookies'] = {}
    return session['cookies'].get(domain, {})

def store_cookies_for_domain(domain, cookies):
    """Store cookies for a specific domain"""
    if 'cookies' not in session:
        session['cookies'] = {}
    if domain not in session['cookies']:
        session['cookies'][domain] = {}
    session['cookies'][domain].update(cookies)
    session.modified = True

def parse_set_cookie_header(response):
    """Parse Set-Cookie header from response and return cookie dict"""
    cookies = {}
    
    # Use requests' built-in cookie handling which is more reliable
    if hasattr(response, 'cookies') and response.cookies:
        for cookie in response.cookies:
            cookies[cookie.name] = cookie.value
    
    # Fallback: try to parse Set-Cookie header manually if no cookies found
    if not cookies and 'Set-Cookie' in response.headers:
        set_cookie_value = response.headers.get('Set-Cookie')
        if set_cookie_value:
            try:
                cookie = SimpleCookie()
                cookie.load(set_cookie_value)
                for key, morsel in cookie.items():
                    cookies[key] = morsel.value
            except Exception:
                # Basic parsing as last resort
                if '=' in set_cookie_value:
                    parts = set_cookie_value.split(';')[0]  # Get only the name=value part
                    if '=' in parts:
                        name, value = parts.split('=', 1)
                        cookies[name.strip()] = value.strip()
    
    return cookies

@app.route('/')
def home():
    with open('index.html', 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/cookies')
def manage_cookies():
    """Display and manage stored cookies"""
    cookies = session.get('cookies', {})
    
    html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cookie Manager - Browse with Freedom</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #0d1117;
            color: #ecf0f1;
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        h1 {
            color: #3498db;
            margin-bottom: 2rem;
            text-align: center;
        }
        .domain-section {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid #3498db;
            border-radius: 8px;
            margin-bottom: 1rem;
            padding: 1rem;
        }
        .domain-header {
            font-size: 1.2rem;
            font-weight: 600;
            color: #3498db;
            margin-bottom: 0.5rem;
        }
        .cookie-item {
            background: rgba(255, 255, 255, 0.02);
            padding: 0.5rem;
            margin: 0.25rem 0;
            border-radius: 4px;
            font-family: monospace;
        }
        .no-cookies {
            text-align: center;
            color: #95a5a6;
            font-style: italic;
            margin: 2rem 0;
        }
        .clear-button {
            background-color: #e74c3c;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 0.5rem;
        }
        .clear-button:hover {
            background-color: #c0392b;
        }
        .back-link {
            display: inline-block;
            color: #3498db;
            text-decoration: none;
            margin-bottom: 2rem;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .clear-all-button {
            background-color: #e74c3c;
            color: white;
            border: none;
            padding: 1rem 2rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            margin: 2rem auto;
            display: block;
        }
        .clear-all-button:hover {
            background-color: #c0392b;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← Back to Home</a>
        <h1>Cookie Manager</h1>
        
        {% if cookies %}
            {% for domain, domain_cookies in cookies.items() %}
            <div class="domain-section">
                <div class="domain-header">{{ domain }}</div>
                {% for name, value in domain_cookies.items() %}
                <div class="cookie-item">
                    <strong>{{ name }}:</strong> {{ value[:50] }}{% if value|length > 50 %}...{% endif %}
                </div>
                {% endfor %}
                <form method="POST" action="/cookies/clear/{{ domain }}" style="display: inline;">
                    <button type="submit" class="clear-button">Clear cookies for {{ domain }}</button>
                </form>
            </div>
            {% endfor %}
            
            <form method="POST" action="/cookies/clear-all">
                <button type="submit" class="clear-all-button" onclick="return confirm('Are you sure you want to clear all cookies?')">Clear All Cookies</button>
            </form>
        {% else %}
            <div class="no-cookies">No cookies stored yet. Visit some websites to see cookies here.</div>
        {% endif %}
    </div>
</body>
</html>
    '''
    
    from flask import render_template_string
    return render_template_string(html, cookies=cookies)

@app.route('/cookies/clear/<domain>', methods=['POST'])
def clear_domain_cookies(domain):
    """Clear cookies for a specific domain"""
    if 'cookies' in session and domain in session['cookies']:
        del session['cookies'][domain]
        session.modified = True
    return redirect('/cookies')

@app.route('/cookies/clear-all', methods=['POST'])
def clear_all_cookies():
    """Clear all stored cookies"""
    session['cookies'] = {}
    session.modified = True
    return redirect('/cookies')

@app.route('/browse')
def browse():
    raw_url = request.args.get('url')
    if not raw_url:
        return redirect('/')
    
    # Ensure valid scheme
    if not raw_url.startswith("http"):
        raw_url = "http://" + raw_url

    # Get domain for cookie handling
    parsed_url = urlparse(raw_url)
    domain = parsed_url.netloc
    
    # Prepare cookies for the request
    stored_cookies = get_cookies_for_domain(domain)
    
    # Fetch content with redirect handling and cookie support
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        resp = requests.get(raw_url, headers=headers, cookies=stored_cookies, allow_redirects=True)
        # Always use the final URL (after any redirects) as the base URL
        final_url = resp.url
        
        # Handle cookies from the response
        if 'Set-Cookie' in resp.headers:
            new_cookies = parse_set_cookie_header(resp)
            store_cookies_for_domain(domain, new_cookies)
    except Exception as e:
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Browse with freedom</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #2c3e50;
        }
        .error-container {
            text-align: center;
            padding: 4rem 2rem;
            max-width: 500px;
            width: 90%;
        }
        .error-title {
            font-size: 2.5rem;
            font-weight: 300;
            margin-bottom: 2rem;
            color: #2c3e50;
        }
        .error-message {
            font-size: 1.1rem;
            margin-bottom: 3rem;
            color: #7f8c8d;
            line-height: 1.6;
        }
        .back-button {
            display: inline-block;
            padding: 1rem 2rem;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            transition: background-color 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1rem;
        }
        .back-button:hover {
            background-color: #2980b9;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1 class="error-title">Something went wrong</h1>
        <p class="error-message">Unable to fetch {{ url }}: {{ error }}</p>
        <a href="/" class="back-button">Go back home</a>
    </div>
</body>
</html>
        ''', url=raw_url, error=str(e))

    content_type = resp.headers.get("content-type", "")

    # If it's HTML, rewrite links
    if "text/html" in content_type:
        soup = BeautifulSoup(resp.text, "html.parser")

        # Don't inject base tag as it can interfere with page functionality
        # Instead rely on comprehensive URL rewriting

        # Rewrite various tags with URLs - comprehensive approach
        url_attributes = {
            'a': ['href'],
            'img': ['src', 'srcset'],
            'script': ['src'],
            'link': ['href'],
            'form': ['action'],
            'iframe': ['src'],
            'embed': ['src'],
            'object': ['data'],
            'source': ['src', 'srcset'],
            'video': ['src', 'poster'],
            'audio': ['src'],
            'track': ['src'],
            'meta': ['content'],
            'area': ['href'],
            'base': ['href']
        }
        
        for tag_name, attributes in url_attributes.items():
            for tag in soup.find_all(tag_name):
                for attr in attributes:
                    if tag.has_attr(attr) and tag[attr]:
                        original = tag[attr]
                        
                        # Special handling for meta tags - only rewrite if it looks like a URL
                        if tag_name == 'meta':
                            if not (original.startswith(('http://', 'https://', '//', '/')) and 
                                   ('url' in tag.get('property', '').lower() or 
                                    'url' in tag.get('name', '').lower())):
                                continue
                        
                        # Special handling for srcset attribute
                        if attr == 'srcset':
                            srcset_parts = []
                            for part in original.split(','):
                                part = part.strip()
                                if ' ' in part:
                                    url_part, descriptor = part.rsplit(' ', 1)
                                    if not url_part.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                                        new_url = urljoin(final_url, url_part.strip())
                                        srcset_parts.append(f"/browse?url={quote(new_url)} {descriptor}")
                                    else:
                                        srcset_parts.append(part)
                                else:
                                    if not part.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                                        new_url = urljoin(final_url, part)
                                        srcset_parts.append(f"/browse?url={quote(new_url)}")
                                    else:
                                        srcset_parts.append(part)
                            tag[attr] = ', '.join(srcset_parts)
                        else:
                            # Skip javascript:, mailto:, tel:, data: URLs and fragments
                            if original.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                                continue
                            new_url = urljoin(final_url, original)
                            tag[attr] = "/browse?url=" + quote(new_url)

        # Handle CSS with url() references
        for style_tag in soup.find_all("style"):
            if style_tag.string:
                css_content = style_tag.string
                # Replace url() references in CSS
                def replace_css_url(match):
                    url = match.group(1).strip('"\'')
                    if url.startswith(("data:", "http")):
                        return match.group(0)
                    new_url = urljoin(final_url, url)
                    return f'url("/browse?url={quote(new_url)}")'
                
                css_content = re.sub(r'url\(["\']?([^"\')]+)["\']?\)', replace_css_url, css_content)
                style_tag.string = css_content

        # Handle inline style attributes
        for tag in soup.find_all(attrs={"style": True}):
            style_content = tag["style"]
            def replace_inline_css_url(match):
                url = match.group(1).strip('"\'')
                if url.startswith(("data:", "http")):
                    return match.group(0)
                new_url = urljoin(final_url, url)
                return f'url("/browse?url={quote(new_url)}")'
            
            style_content = re.sub(r'url\(["\']?([^"\')]+)["\']?\)', replace_inline_css_url, style_content)
            tag["style"] = style_content

        # Check if current site should show warning overlay
        parsed_url = urlparse(final_url)
        domain = parsed_url.netloc.lower()
        
        # Remove www. prefix for comparison
        if domain.startswith('www.'):
            domain = domain[4:]
        
        should_show_warning = False
        for warning_site in config.get('warning_sites', []):
            if warning_site.lower() in domain or domain.endswith('.' + warning_site.lower()):
                should_show_warning = True
                break
        
        # Inject warning overlay if needed
        if should_show_warning and config.get('warning_message'):
            warning_html = create_warning_overlay(config)
            # Insert before closing body tag
            body_tag = soup.find('body')
            if body_tag:
                warning_soup = BeautifulSoup(warning_html, 'html.parser')
                body_tag.append(warning_soup)
            else:
                # If no body tag, append to html
                html_tag = soup.find('html')
                if html_tag:
                    warning_soup = BeautifulSoup(warning_html, 'html.parser')
                    html_tag.append(warning_soup)

        return Response(str(soup), content_type="text/html")

    # Otherwise (CSS, JS, images, etc.)
    return Response(resp.content, content_type=content_type)

def create_warning_overlay(config):
    """Create HTML for warning overlay"""
    message = config.get('warning_message', 'Warning: This site may be restricted.')
    style = config.get('warning_style', {})
    
    # Default styles
    default_style = {
        'background_color': '#ff6b6b',
        'text_color': '#ffffff',
        'font_size': '14px',
        'padding': '10px 20px',
        'position': 'fixed',
        'bottom': '0',
        'left': '0',
        'right': '0',
        'z_index': '9999',
        'text_align': 'center',
        'box_shadow': '0 -2px 10px rgba(0,0,0,0.3)'
    }
    
    # Merge with config styles
    final_style = {**default_style, **style}
    
    # Convert style dict to CSS string
    css_style = '; '.join([f"{k.replace('_', '-')}: {v}" for k, v in final_style.items()])
    
    return f'''
    <div id="proxy-warning-overlay" style="{css_style}">
        <span>{message}</span>
        <button onclick="document.getElementById('proxy-warning-overlay').style.display='none'" 
                 style="margin-left: 15px; background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3); 
                        color: white; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 12px;">
             Close
         </button>
    </div>
    '''

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_path(path):
    """Handle all other paths by proxying them to the current site"""
    # Get the referer to determine which site we're proxying
    referer = request.headers.get('Referer', '')
    
    print(f"DEBUG: Proxy path request - Path: {path}, Referer: {referer}")
    
    if '/browse?url=' in referer:
        # Extract the original URL from the referer
        try:
            match = re.search(r'/browse\?url=([^&\s]+)', referer)
            if match:
                original_url = unquote(match.group(1))
                
                # Ensure the URL has a scheme
                if not original_url.startswith(('http://', 'https://')):
                    original_url = 'http://' + original_url
                
                parsed_original = urlparse(original_url)
                base_url = f"{parsed_original.scheme}://{parsed_original.netloc}"
                
                # Construct the target URL
                target_url = f"{base_url}/{path}"
                if request.query_string:
                    target_url += f"?{request.query_string.decode()}"
                
                print(f"DEBUG: Target URL: {target_url}")
                
                # Forward the request
                try:
                    # Get domain for cookie handling
                    target_parsed = urlparse(target_url)
                    target_domain = target_parsed.netloc
                    stored_cookies = get_cookies_for_domain(target_domain)
                    
                    # Create clean headers
                    clean_headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        'Accept': request.headers.get('Accept', '*/*'),
                        'Accept-Language': request.headers.get('Accept-Language', 'en-US,en;q=0.9'),
                        'Accept-Encoding': 'gzip, deflate'
                    }
                    
                    # Add referer if it exists
                    if 'Referer' in request.headers:
                        clean_headers['Referer'] = original_url
                    
                    if request.method == 'GET':
                        resp = requests.get(target_url, headers=clean_headers, cookies=stored_cookies, allow_redirects=True, timeout=10)
                    elif request.method == 'POST':
                        resp = requests.post(target_url, headers=clean_headers, cookies=stored_cookies, data=request.get_data(), allow_redirects=True, timeout=10)
                    else:
                        resp = requests.request(request.method, target_url, headers=clean_headers, cookies=stored_cookies, data=request.get_data(), allow_redirects=True, timeout=10)
                    
                    # Handle cookies from the response
                    if 'Set-Cookie' in resp.headers:
                        new_cookies = parse_set_cookie_header(resp)
                        store_cookies_for_domain(target_domain, new_cookies)
                    
                    print(f"DEBUG: Response status: {resp.status_code}")
                    
                    # Return the response
                    response = Response(resp.content, status=resp.status_code)
                    
                    # Copy safe headers
                    safe_headers = ['content-type', 'cache-control', 'expires', 'last-modified', 'etag']
                    for header in safe_headers:
                        if header in resp.headers:
                            response.headers[header] = resp.headers[header]
                    
                    return response
                    
                except Exception as e:
                    print(f"DEBUG: Error proxying request: {str(e)}")
                    return Response(f"Error proxying request: {str(e)}", status=500)
        except Exception as e:
            print(f"DEBUG: Error parsing referer: {str(e)}")
            pass
    
    print(f"DEBUG: No valid referer found, redirecting to home")
    # If we can't determine the target, redirect to home
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
