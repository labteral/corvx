<p align="center">
<img src="misc/corvx.svg" alt="corvx Logo" width="150"/></a>
</p>

<p align="center">
    <a href="https://pepy.tech/project/corvx/"><img alt="Downloads" src="https://img.shields.io/badge/dynamic/json?style=flat-square&maxAge=3600&label=downloads&query=$.total_downloads&url=https://api.pepy.tech/api/projects/corvx"></a>
    <a href="https://pypi.python.org/pypi/corvx/"><img alt="PyPi" src="https://img.shields.io/pypi/v/corvx.svg?style=flat-square"></a>
    <!--<a href="https://github.com/labteral/corvx/releases"><img alt="GitHub releases" src="https://img.shields.io/github/release/labteral/corvx.svg?style=flat-square"></a>-->
    <a href="https://github.com/labteral/corvx/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/labteral/corvx.svg?style=flat-square&color=green"></a>
</p>

<h3 align="center">
<b>An unofficial X SDK for Python</b>
</h3>

<p align="center">
    <a href="https://www.buymeacoffee.com/labteral" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="35px"></a>
</p>

# Installation

> corvx works with Python +3.10

You can install the `corvx` package directly with `pip`:
```bash
pip install -e .
```
or 
```bash
pip install corvx
```

# Usage

To work with the X Scraper module you have to import the corresponding module first:

```python
from corvx import Corvx

# You can also set the tokens with environment variables X_AUTH_TOKEN and X_CSRF_TOKEN
corvx = Corvx(
    auth_token=os.getenv('X_AUTH_TOKEN'),
    csrf_token=os.getenv('X_CSRF_TOKEN'),
)
```

The available methods and its usage are described below.

## Query Formats

corvx supports two query formats:

### 1. Simple String Format

You can directly pass strings as queries:

```python
queries = [
    'python programming',
    'javascript development',
]

for tweet in corvx.search(queries=queries):
    print(tweet)
```

### 2. Advanced Query Language

For more complex searches, a JSON-based query language is available.
The query must be specified as a Python dictionary containing a list of fields and global options.

### Global options

---

#### lang

This option will force the tweets to match a given language. The language must be specified with its ISO 639-1 two-letter code (e.g., `es` for Spanish).

#### since

This parameter refers to the minimum allowed date. It has to be specified in the `YYYY-MM-DD` format.

#### until

This parameter refers to the maximum allowed date. It has to be specified in the `YYYY-MM-DD` format.

#### near

It has to be specified with a `tuple` object composed of a text location and a range in miles (e.g., `('Santiago de Compostela', 15)`).

### Fields

---

A query can specify multiple fields which are Python dictionaries with one or more keys and values:

#### items

This is a list of strings, either terms or phrases.

#### exact

If `True`, the specified terms or phrases must match exactly as they were written on the tweets (case/latin insensitive). If this flag is set, the `target` parameter will be ignored.

#### match

If not specified, the tweets will match every item.

- `'any'` (the tweets must match at least one of the items)
- `'none'` (the tweets won't match any item)

#### target

If not specified, the tweets will match ordinary keywords.

- `'hashtag'` (tweets containing `#item`)
- `'mention'` (tweets mentioning `@item`)
- `'from'` (tweets written by `@item`)
- `'to'` (tweets that are replies to `@item`)

### Examples

---

Simple search with multiple queries:

```python
# Simple string queries
queries = ['python', 'javascript']
for tweet in corvx.search(queries=queries):
    print(tweet)
```

Advanced search with a single query:

```python
# Advanced query format
query = {
    'fields': [
        {'items': ['Santiago']},
        {'items': ['Chile'], 'match': 'none'},
    ],
    'lang': 'es'
}

for tweet in corvx.search(query=query):
    print(tweet)
```

Advanced search with multiple queries:

```python
# Multiple advanced queries
queries = [
    {
        'fields': [{'items': ['python'], 'match': 'any'}],
        'lang': 'en'
    },
    {
        'fields': [{'items': ['javascript'], 'match': 'any'}],
        'lang': 'en'
    }
]

for tweet in corvx.search(queries=queries):
    print(tweet)
```

## Search Options

### Deep Search

Search for all available results by going back in time:

```python
for tweet in corvx.search(queries=queries, deep=True):
    print(tweet)
```

### Limit Results

Limit the number of results:

```python
for tweet in corvx.search(queries=queries, limit=100):
    print(tweet)
```

### Rate Limiting

Control the time between API calls:

```python
for tweet in corvx.search(queries=queries, sleep_time=30):
    print(tweet)
```

## Stream

Search constantly for new results:

```python
# Stream with multiple queries
queries = ['python', 'javascript']
for tweet in corvx.stream(queries=queries, sleep_time=30):
    print(tweet)
```

Control how long the search should pause between iterations when no new
posts are found using the `sleep_time` parameter (defaults to 20 seconds).

## Debug Logging

Enable debug logging to see detailed information:

```python
import logging

# Configure logging at the start of your script
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

# Configure corvx logger
logger = logging.getLogger('corvx')
logger.setLevel(logging.DEBUG)
logger.propagate = True
```
