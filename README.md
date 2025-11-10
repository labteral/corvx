# Corvx

An unofficial X (Twitter) SDK for Python.

## Overview

Corvx is a Python library for interacting with X's (formerly Twitter) GraphQL API. It provides a simple interface for searching and retrieving tweets programmatically.

## Requirements

- Python >= 3.10
- Dependencies:
  - `requests` - HTTP library
  - `beautifulsoup4` - HTML parsing
  - `ordered-set` - Data structure utilities
  - `xclienttransaction` - X-Client-Transaction-Id generation

## Installation

```bash
pip install corvx
```

For development:
```bash
pip install corvx[dev]
```

## Authentication

Corvx requires two authentication tokens from X:

1. **auth_token**: Your X authentication token (cookie)
2. **csrf_token** (ct0): Your CSRF token (cookie)

### Getting Your Tokens

1. Log in to X (twitter.com/x.com) in your browser
2. Open Developer Tools (F12)
3. Go to Application/Storage → Cookies → https://x.com
4. Copy the values for:
   - `auth_token`
   - `ct0` (this is your CSRF token)

### Setting Tokens

**Option 1: Environment Variables**
```bash
export X_AUTH_TOKEN="your_auth_token_here"
export X_CSRF_TOKEN="your_csrf_token_here"
```

**Option 2: Pass to Constructor**
```python
from corvx import Corvx

corvx = Corvx(
    auth_token="your_auth_token_here",
    csrf_token="your_csrf_token_here"
)
```

## Usage

### Basic Search

```python
from corvx import Corvx

# Initialize
corvx = Corvx(
    auth_token="your_auth_token",
    csrf_token="your_csrf_token"
)

# Simple search - returns first 20 tweets
for tweet in corvx.search("python", limit=20):
    print(f"@{tweet['username']}: {tweet['text']}")
    print(f"Tweet ID: {tweet['id']}")
    print()
```

### Search Parameters

```python
corvx.search(
    query="keyword",        # Search query (string or dict)
    deep=False,            # If True, paginate backwards until no results
    fast=False,            # Stop when cursor repeats (use with deep=True)
    limit=None,            # Max tweets to retrieve (None = unlimited)
    sleep_time=20          # Delay between requests (seconds)
)
```

### Deep Search (Historical Data)

```python
# Get as many tweets as possible going back in time
for tweet in corvx.search("climate change", deep=True, limit=1000):
    print(tweet['text'])
```

### Advanced Query Format

```python
# Use dictionary for more control
query = {
    'rawQuery': 'python programming',
    'count': 20,
    'querySource': 'typed_query',
    'product': 'Latest'
}

for tweet in corvx.search(query, limit=100):
    print(tweet)
```

### Multiple Queries

```python
# Search multiple keywords
queries = ["python", "javascript", "rust"]

for tweet in corvx.search(queries, limit=50):
    print(f"Query: {tweet['raw_query']}")
    print(f"Tweet: {tweet['text']}")
    print()
```

## Tweet Data Structure

Each tweet dictionary contains:

```python
{
    'id': '1234567890',
    'username': 'example_user',
    'text': 'Tweet content here...',
    'created_at': '2024-01-01T12:00:00.000Z',
    'raw_query': 'python',  # The query that returned this tweet
    # ... additional fields
}
```

## Error Handling

```python
from corvx import Corvx, NoResultsError

corvx = Corvx(auth_token="...", csrf_token="...")

try:
    results = list(corvx.search("obscure_query", limit=10))
    if not results:
        print("No tweets found")
except NoResultsError:
    print("Query returned no results")
except Exception as e:
    print(f"Error: {e}")
```

## Rate Limiting

X enforces rate limits. Corvx handles this automatically by:

- Sleeping 15 minutes when rate limited (HTTP 429)
- Default 20-second delay between requests
- Customizable via `sleep_time` parameter

```python
# Faster requests (higher risk of rate limiting)
corvx.search("query", sleep_time=5, limit=100)

# Slower, safer requests
corvx.search("query", sleep_time=60, limit=1000)
```

## Technical Details

### Current API Endpoint

Corvx uses X's GraphQL SearchTimeline endpoint:
- Endpoint ID: `7r8ibjHuK3MWUyzkzHNMYQ`
- Base URL: `https://x.com/i/api/graphql/7r8ibjHuK3MWUyzkzHNMYQ/SearchTimeline`

### Required Headers

The library automatically includes required headers:
- `Authorization`: Bearer token
- `X-Csrf-Token`: CSRF token from cookies
- `X-Twitter-Active-User`: yes
- `X-Twitter-Auth-Type`: OAuth2Session
- `X-Client-Transaction-Id`: Generated per request
- `Sec-Fetch-*`: Browser security headers
- `User-Agent`: Browser identification

### Transaction ID Generation

Corvx uses the `xclienttransaction` library to generate fresh transaction IDs for each request, matching X's browser behavior.

## Logging

Enable debug logging to see request details:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('corvx')
logger.setLevel(logging.DEBUG)

# Now search will log detailed information
corvx.search("test", limit=5)
```

## Common Issues

### 401 Unauthorized
- Invalid or expired `auth_token`/`csrf_token`
- Solution: Get fresh tokens from your browser

### 429 Rate Limited
- Too many requests
- Solution: Increase `sleep_time` or wait 15 minutes

### 404 Not Found
- API endpoint changed (rare)
- Check library version is up to date

## Development

```bash
# Clone repository
git clone https://github.com/labteral/corvx.git
cd corvx

# Install development dependencies
pip install -e .[dev]

# Run tests
python test.py
```

## License

GNU General Public License v3 (GPLv3)

## Author

Rodrigo Martínez (dev@brunneis.com)

## Repository

https://github.com/labteral/corvx

## Disclaimer

This is an unofficial library and is not affiliated with X Corp. Use at your own risk. Respect X's Terms of Service and API usage policies.
