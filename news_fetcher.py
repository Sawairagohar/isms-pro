import feedparser
import logging
import re
from datetime import datetime

logging.basicConfig(filename='logs/news.log', level=logging.INFO)

# Real cybersecurity RSS feeds
SECURITY_FEEDS = [
    {
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "Threat Intelligence",
        "source": "The Hacker News"
    },
    {
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "Security News",
        "source": "BleepingComputer"
    },
    {
        "url": "https://krebsonsecurity.com/feed/",
        "category": "Cybersecurity",
        "source": "Krebs on Security"
    },
    {
        "url": "https://www.darkreading.com/rss.xml",
        "category": "Enterprise Security",
        "source": "Dark Reading"
    },
    {
        "url": "https://www.schneier.com/feed/atom/",
        "category": "Security Research",
        "source": "Schneier on Security"
    },
]

def clean_html(text):
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'&nbsp;', ' ', clean)
    clean = re.sub(r'&amp;', '&', clean)
    clean = re.sub(r'&lt;', '<', clean)
    clean = re.sub(r'&gt;', '>', clean)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

def make_slug(title):
    slug = title.lower()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'\s+', '-', slug)
    slug = slug[:100]
    return slug + f"-{int(datetime.now().timestamp())}"

def fetch_security_news(app, db, BlogPost):
    with app.app_context():
        total_added = 0
        for feed_info in SECURITY_FEEDS:
            try:
                logging.info(f"Fetching from {feed_info['source']}...")
                feed = feedparser.parse(feed_info['url'])
                for entry in feed.entries[:5]:
                    title   = clean_html(entry.get('title', ''))
                    summary = clean_html(entry.get('summary', entry.get('description', '')))
                    link    = entry.get('link', '')
                    if not title or not summary:
                        continue
                    # Check if already exists
                    existing = BlogPost.query.filter_by(
                        title=title[:299]
                    ).first()
                    if existing:
                        continue
                    # Get image if available
                    image_url = None
                    if hasattr(entry, 'media_content'):
                        for media in entry.media_content:
                            if 'url' in media:
                                image_url = media['url']
                                break
                    # Get tags
                    tags = []
                    if hasattr(entry, 'tags'):
                        tags = [t.term for t in entry.tags[:5]]
                    post = BlogPost(
                        title=title[:299],
                        slug=make_slug(title),
                        category=feed_info['category'],
                        summary=summary[:500],
                        content=summary,
                        author=feed_info['source'],
                        source_url=link,
                        image_url=image_url,
                        is_auto=True,
                        tags=', '.join(tags)
                    )
                    db.session.add(post)
                    total_added += 1
                db.session.commit()
                logging.info(f"Added {total_added} posts from {feed_info['source']}")
            except Exception as e:
                logging.error(f"Feed error {feed_info['source']}: {e}")
        logging.info(f"Total new posts added: {total_added}")
        return total_added
