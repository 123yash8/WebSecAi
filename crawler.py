from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

def generate_sitemap(start_url):
    visited = set()
    to_visit = [start_url]
    sitemap = []

    while to_visit:
        url = to_visit.pop(0)
        if url in visited:
            continue
        
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                sitemap.append(url)
                soup = BeautifulSoup(res.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if urlparse(full_url).netloc == urlparse(start_url).netloc:
                        to_visit.append(full_url)
                
                visited.add(url)
        except Exception:
            continue
    
    return sitemap