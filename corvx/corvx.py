import json
import time
import urllib.parse
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Generator

import requests
import os

from .structures import CircularOrderedSet


# Configure logging
logger = logging.getLogger('corvx')

# Only add handler if none exists to avoid duplicate handlers
if not logger.handlers:
    # Create console handler with a higher log level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    # Add formatter to console handler
    console_handler.setFormatter(formatter)

    # Add console handler to the logger
    logger.addHandler(console_handler)


class Corvx:
    X_CLIENT_TOKEN = (
        'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs'
        '%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'
    )
    X_AUTH_TOKEN = os.getenv('X_AUTH_TOKEN')
    X_CSRF_TOKEN = os.getenv('X_CSRF_TOKEN')

    def __init__(
        self,
        auth_token: Optional[str] = None,
        csrf_token: Optional[str] = None,
    ):
        self.auth_token = auth_token or self.X_AUTH_TOKEN
        self.csrf_token = csrf_token or self.X_CSRF_TOKEN
        self.headers = {
            'Cookie': 'auth_token={0}; ct0={1}'.format(
                self.auth_token,
                self.csrf_token,
            ),
            'X-Csrf-Token': self.csrf_token,
            'Authorization': 'Bearer {0}'.format(self.X_CLIENT_TOKEN),
        }

    @staticmethod
    def _update_url_with_params(url: str, params: Dict[str, str]) -> str:
        first = True
        for key, value in params.items():
            symbol = '&' if not first else '?'
            first = False
            url += '{0}{1}={2}'.format(symbol, key, value)
        return url

    @staticmethod
    def _encode_query(query: Dict[str, Any]) -> str:
        encoded_query = ''
        since = query.get('since')
        until = query.get('until')
        near = query.get('near')
        lang = query.get('lang')
        fields = query.get('fields', [])

        for field in fields:
            target = field.get('target')
            items = field['items']
            match = field.get('match')
            exact = field.get('exact', False)

            if exact:
                marginal_query = '"{0}"'.format('" "'.join(items))
            else:
                if target == 'from':
                    marginal_query = 'from:{0}'.format(' from:'.join(items))
                elif target == 'to':
                    marginal_query = 'to:{0}'.format(' to:'.join(items))
                elif target == 'hashtag':
                    marginal_query = '#{0}'.format(' #'.join(items))
                elif target == 'mention':
                    marginal_query = '@{0}'.format(' @'.join(items))
                else:
                    marginal_query = ' '.join(items)

            if match == 'any':
                marginal_query = ' OR '.join(marginal_query.split())
            elif match == 'none':
                marginal_query = '-{0}'.format(
                    ' -'.join(marginal_query.split()),
                )

            encoded_query += (
                ' ({0})'.format(marginal_query) if match == 'any'
                else ' {0}'.format(marginal_query)
            )

        if since:
            encoded_query += ' since:{0}'.format(since)
        if until:
            encoded_query += ' until:{0}'.format(until)
        if near:
            encoded_query += ' near:"{0}" within:{1}mi'.format(
                near[0],
                near[1],
            )

        encoded_query = encoded_query.strip()

        if lang:
            encoded_query += ' lang:{0}'.format(lang)

        logger.debug('[Test URL] https://twitter.com/search?q={0}'.format(
            urllib.parse.quote(encoded_query).replace('%20', '+'),
        ) + '&src=typed_query&f=live')

        return encoded_query

    def get_url(self, query: str, cursor: Optional[str] = None) -> str:
        base_url = ('https://x.com/i/api/graphql/'
                    'MJpyQGqgklrVl_0X9gNy3A/SearchTimeline')

        payload = {
            'variables': {
                'rawQuery': query,
                'count': 20,
                'querySource': 'typed_query',
                'product': 'Latest',
            },
            'features': {
                'rweb_tipjar_consumption_enabled': True,
                'responsive_web_graphql_exclude_directive_enabled': True,
                'verified_phone_label_enabled': False,
                'creator_subscriptions_tweet_preview_api_enabled': True,
                'responsive_web_graphql_timeline_navigation_enabled': True,
                'responsive_web_graphql_skip_user_profile_image_extensions_'
                'enabled': False,
                'communities_web_enable_tweet_community_results_fetch': True,
                'c9s_tweet_anatomy_moderator_badge_enabled': True,
                'articles_preview_enabled': True,
                'responsive_web_edit_tweet_api_enabled': True,
                'graphql_is_translatable_rweb_tweet_is_translatable_'
                'enabled': True,
                'view_counts_everywhere_api_enabled': True,
                'longform_notetweets_inline_media_enabled': True,
                'longform_notetweets_consumption_enabled': True,
                'longform_notetweets_rich_text_read_enabled': True,
                'responsive_web_twitter_article_tweet_consumption_'
                'enabled': True,
                'tweet_awards_web_tipping_enabled': False,
                'creator_subscriptions_quote_tweet_preview_enabled': False,
                'freedom_of_speech_not_reach_fetch_enabled': True,
                'standardized_nudges_misinfo': True,
                'tweet_with_visibility_results_prefer_gql_limited_'
                'actions_policy_enabled': True,
                'rweb_video_timestamps_enabled': True,
                'responsive_web_enhance_cards_enabled': False,
            },
        }

        if cursor is not None:
            payload['variables']['cursor'] = cursor

        url = base_url
        url += '?variables={0}'.format(
            urllib.parse.quote(json.dumps(payload['variables'])),
        )
        url += '&features={0}'.format(
            urllib.parse.quote(json.dumps(payload['features'])),
        )

        return url

    def search(
        self,
        query: Optional[Dict[str, Any]] = None,
        queries: Optional[list[Dict[str, Any]]] = None,
        deep: bool = False,
        limit: Optional[int] = None,
        sleep_time: float = 20,
    ) -> Generator[Dict[str, Any], None, None]:
        # Handle both single and multiple queries
        if queries is None and query is not None:
            queries = [query]
        elif queries is None and query is None:
            raise ValueError('Either queries or query must be provided')

        # Ensure all queries are dictionaries
        queries = [
            (query_obj if isinstance(query_obj, dict)
             else {'fields': [{'items': [query_obj]}]})
            for query_obj in queries
        ]

        # Track last API call time to respect rate limits across queries
        last_api_call = 0.0
        known_posts = set()
        posts_yielded = 0
        new_posts_in_iteration = {
            query_idx: 0 for query_idx in range(len(queries))
        }
        consecutive_empty_days = {
            query_idx: 0 for query_idx in range(len(queries))
        }

        # For deep search, initialize date boundaries for each query
        current_dates = {}
        min_dates = {}
        if deep:
            for query_idx, current_query in enumerate(queries):
                # Start with today's date
                current_until = datetime.now().date()

                # If until is set, use it as the upper boundary
                if 'until' in current_query:
                    query_until = datetime.strptime(
                        current_query['until'],
                        '%Y-%m-%d',
                    ).date()
                    current_until = min(current_until, query_until)

                # Store the lower boundary if since is set
                min_date = None
                if 'since' in current_query:
                    min_date = datetime.strptime(
                        current_query['since'],
                        '%Y-%m-%d',
                    ).date()

                # Set initial date range
                current_since = current_until - timedelta(days=1)
                if min_date and current_since < min_date:
                    continue

                current_dates[query_idx] = {
                    'until': current_until,
                    'since': current_since,
                }
                min_dates[query_idx] = min_date

                # Update query with date range
                query_copy = current_query.copy()
                query_copy['until'] = current_until.strftime('%Y-%m-%d')
                query_copy['since'] = current_since.strftime('%Y-%m-%d')
                queries[query_idx] = query_copy

        cursors = {query_idx: None for query_idx in range(len(queries))}
        previous_cursors = {
            query_idx: None for query_idx in range(len(queries))}
        encoded_queries = {
            query_idx: self._encode_query(query_obj)
            for query_idx, query_obj in enumerate(queries)
        }
        active_queries = set(range(len(queries)))

        while active_queries:
            new_posts_found = False

            # Process one page from each active query
            for query_idx in list(active_queries):
                current_query = queries[query_idx]
                current_cursor = cursors[query_idx]
                prev_cursor = previous_cursors[query_idx]
                encoded_query = encoded_queries[query_idx]

                if current_cursor and prev_cursor == current_cursor:
                    if not deep:
                        active_queries.remove(query_idx)
                        continue

                    # Move to previous day if we got new posts
                    if new_posts_in_iteration[query_idx] > 0:
                        consecutive_empty_days[query_idx] = 0  # Reset counter
                        current_dates[query_idx]['until'] = (
                            current_dates[query_idx]['since']
                        )
                        current_dates[query_idx]['since'] = (
                            current_dates[query_idx]['until'] -
                            timedelta(days=1)
                        )

                        # Stop if we hit the minimum date
                        query_min_date = min_dates[query_idx]
                        query_since = current_dates[query_idx]['since']
                        if query_min_date and query_since < query_min_date:
                            active_queries.remove(query_idx)
                            continue

                        # Update query with date range
                        query_copy = current_query.copy()
                        query_until = (
                            current_dates[query_idx]['until'].strftime(
                                '%Y-%m-%d',
                            )
                        )
                        query_since = (
                            current_dates[query_idx]['since'].strftime(
                                '%Y-%m-%d',
                            )
                        )
                        query_copy['until'] = query_until
                        query_copy['since'] = query_since
                        encoded_queries[query_idx] = self._encode_query(
                            query_copy)
                        encoded_query = encoded_queries[query_idx]
                        new_posts_in_iteration[query_idx] = 0
                        cursors[query_idx] = None
                        previous_cursors[query_idx] = None
                        continue

                    # No new posts, count empty day
                    consecutive_empty_days[query_idx] += 1
                    if consecutive_empty_days[query_idx] >= 30:
                        active_queries.remove(query_idx)  # Skip this query
                        continue

                    # Move to previous day
                    current_dates[query_idx]['until'] = (
                        current_dates[query_idx]['since']
                    )
                    current_dates[query_idx]['since'] = (
                        current_dates[query_idx]['until'] - timedelta(days=1)
                    )

                    # Stop if we hit the minimum date
                    query_min_date = min_dates[query_idx]
                    query_since = current_dates[query_idx]['since']
                    if query_min_date and query_since < query_min_date:
                        active_queries.remove(query_idx)
                        continue

                    # Update query with date range
                    query_copy = current_query.copy()
                    query_until = (
                        current_dates[query_idx]['until'].strftime(
                            '%Y-%m-%d',
                        )
                    )
                    query_since = (
                        current_dates[query_idx]['since'].strftime(
                            '%Y-%m-%d',
                        )
                    )
                    query_copy['until'] = query_until
                    query_copy['since'] = query_since
                    encoded_queries[query_idx] = self._encode_query(query_copy)
                    encoded_query = encoded_queries[query_idx]
                    new_posts_in_iteration[query_idx] = 0
                    cursors[query_idx] = None
                    previous_cursors[query_idx] = None
                    continue

                # Respect sleep_time between API calls
                time_since_last_call = time.time() - last_api_call
                if time_since_last_call < sleep_time:
                    time.sleep(sleep_time - time_since_last_call)

                previous_cursors[query_idx] = current_cursor

                url = self.get_url(encoded_query, current_cursor)
                response = requests.get(url, headers=self.headers)
                last_api_call = time.time()

                if response.status_code == 401:
                    raise Exception('Unauthorized: Invalid credentials')
                elif response.status_code == 429:
                    logger.warning(
                        'Rate limit exceeded. Sleeping for 15 minutes.',
                    )
                    time.sleep(905)
                    continue
                elif response.status_code != 200:
                    logger.error(
                        'Failed to fetch data. Status code: {0}'.format(
                            response.status_code,
                        ),
                    )
                    logger.error(
                        'Response content: {0}'.format(response.content),
                    )
                    continue

                response_json = response.json()

                try:
                    # Handle different response structures
                    if 'data' not in response_json:
                        logger.warning(
                            'Unexpected response structure. Retrying...',
                        )
                        time.sleep(sleep_time)
                        continue

                    search_data = response_json['data']

                    if 'search_by_raw_query' not in search_data:
                        timeline_data = search_data.get('search_timeline', {})
                    else:
                        timeline_data = search_data['search_by_raw_query'].get(
                            'search_timeline',
                            {},
                        )

                    if not timeline_data or 'timeline' not in timeline_data:
                        logger.warning('No timeline data found. Retrying...')
                        time.sleep(sleep_time)
                        continue

                    instructions = timeline_data['timeline']['instructions']

                except KeyError as error:
                    logger.warning(
                        'Error parsing response structure: {}'.format(
                            str(error)),
                    )
                    time.sleep(sleep_time)
                    continue

                last_instruction = instructions[-1]
                if last_instruction['type'] == 'TimelineReplaceEntry':
                    if (last_instruction['entry']['content']['cursorType'] ==
                            'Bottom'):
                        cursors[query_idx] = (
                            last_instruction['entry']['content']['value']
                        )

                entries = instructions[0].get('entries', [])

                if not entries:
                    if not deep:
                        active_queries.remove(query_idx)
                        continue

                    # No entries found, count empty day
                    consecutive_empty_days[query_idx] += 1
                    if consecutive_empty_days[query_idx] >= 30:
                        active_queries.remove(query_idx)  # Skip this query
                        continue

                    # Move to previous day
                    current_dates[query_idx]['until'] = (
                        current_dates[query_idx]['since']
                    )
                    current_dates[query_idx]['since'] = (
                        current_dates[query_idx]['until'] - timedelta(days=1)
                    )

                    # Stop if we hit the minimum date
                    query_min_date = min_dates[query_idx]
                    query_since = current_dates[query_idx]['since']
                    if query_min_date and query_since < query_min_date:
                        active_queries.remove(query_idx)
                        continue

                    # Update query with date range
                    query_copy = current_query.copy()
                    query_until = (
                        current_dates[query_idx]['until'].strftime('%Y-%m-%d')
                    )
                    query_since = (
                        current_dates[query_idx]['since'].strftime('%Y-%m-%d')
                    )
                    query_copy['until'] = query_until
                    query_copy['since'] = query_since
                    encoded_queries[query_idx] = self._encode_query(query_copy)
                    encoded_query = encoded_queries[query_idx]
                    new_posts_in_iteration[query_idx] = 0
                    cursors[query_idx] = None
                    previous_cursors[query_idx] = None
                    continue

                # Process entries
                for entry in entries:
                    try:
                        data = (entry['content']['itemContent']
                                ['tweet_results']['result'])
                    except KeyError:
                        try:
                            if (entry['content']['entryType'] ==
                                    'TimelineTimelineCursor'):
                                if (entry['content']['cursorType'].lower() ==
                                        'bottom'):
                                    cursors[query_idx] = (
                                        entry['content']['value']
                                    )
                        except KeyError as error:
                            logger.error(
                                'Error processing entry: {}'.format(error),
                            )
                            logger.debug(
                                'Entry details: {}'.format(entry),
                            )
                        continue

                    if 'legacy' not in data:
                        data = data['tweet']

                    tweet = data['legacy']
                    tweet = {
                        'id': data['rest_id'],
                        'created_at': int(datetime.strptime(
                            tweet['created_at'],
                            '%a %b %d %H:%M:%S %z %Y',
                        ).timestamp()),
                        'full_text': tweet['full_text'],
                        'retweet_count': tweet['retweet_count'],
                        'favorite_count': tweet['favorite_count'],
                    }

                    user = data['core']['user_results']['result']
                    user_info = {
                        'name': user['legacy']['name'],
                        'screen_name': user['legacy']['screen_name'],
                    }
                    tweet.update(user_info)

                    if tweet['id'] in known_posts:
                        continue
                    known_posts.add(tweet['id'])
                    new_posts_found = True
                    new_posts_in_iteration[query_idx] += 1

                    tweet['url'] = 'https://twitter.com/{0}/status/{1}'.format(
                        tweet['screen_name'],
                        tweet['id'],
                    )

                    yield tweet
                    posts_yielded += 1

                    if limit is not None and posts_yielded >= limit:
                        return

            if not new_posts_found and not deep:
                return

            if limit is not None and posts_yielded >= limit:
                return

    def stream(
        self,
        query: Optional[Dict[str, Any]] = None,
        queries: Optional[list[Dict[str, Any]]] = None,
        **kwargs,
    ) -> Generator[Dict[str, Any], None, None]:
        known_posts = CircularOrderedSet(100)
        while True:
            try:
                for post in self.search(
                    queries=queries,
                    query=query,
                    **kwargs,
                ):
                    if post['id'] not in known_posts:
                        known_posts.add(post['id'])
                        yield post
            except Exception as e:
                logger.error('Error during post search: {}'.format(str(e)))
