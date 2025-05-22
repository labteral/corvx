import json
import time
import urllib.parse
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Generator, Union

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


class NoResultsError(Exception):
    """Raised when a query yields no posts."""


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
        self.session = requests.Session()
        self.session.headers.update(self.headers)

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
        base_url = (
            'https://x.com/i/api/graphql/'
            'hR4IbVJ4MiRt2dpZOR7ZyQ/SearchTimeline'
        )

        payload = {
            'variables': {
                'rawQuery': query,
                'count': 20,
                'querySource': 'typed_query',
                'product': 'Latest',
            },
            'features': {
                'rweb_video_screen_enabled': False,
                'profile_label_improvements_pcf_label_in_post_enabled': True,
                'rweb_tipjar_consumption_enabled': True,
                'verified_phone_label_enabled': False,
                'creator_subscriptions_tweet_preview_api_enabled': True,
                'responsive_web_graphql_timeline_navigation_enabled': True,
                'responsive_web_graphql_skip_user_profile_image_extensions_'
                'enabled': False,
                'premium_content_api_read_enabled': False,
                'communities_web_enable_tweet_community_results_fetch': True,
                'c9s_tweet_anatomy_moderator_badge_enabled': True,
                'responsive_web_grok_analyze_button_fetch_trends_enabled': False,
                'responsive_web_grok_analyze_post_followups_enabled': True,
                'responsive_web_jetfuel_frame': False,
                'responsive_web_grok_share_attachment_enabled': True,
                'articles_preview_enabled': True,
                'responsive_web_edit_tweet_api_enabled': True,
                'graphql_is_translatable_rweb_tweet_is_translatable_'
                'enabled': True,
                'view_counts_everywhere_api_enabled': True,
                'longform_notetweets_consumption_enabled': True,
                'responsive_web_twitter_article_tweet_consumption_'
                'enabled': True,
                'tweet_awards_web_tipping_enabled': False,
                'responsive_web_grok_show_grok_translated_post': False,
                'responsive_web_grok_analysis_button_from_backend': True,
                'creator_subscriptions_quote_tweet_preview_enabled': False,
                'freedom_of_speech_not_reach_fetch_enabled': True,
                'standardized_nudges_misinfo': True,
                'tweet_with_visibility_results_prefer_gql_limited_'
                'actions_policy_enabled': True,
                'longform_notetweets_rich_text_read_enabled': True,
                'longform_notetweets_inline_media_enabled': True,
                'responsive_web_grok_image_annotation_enabled': True,
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

    def _make_request(
        self,
        url: str,
        sleep_time: float,
        raise_on_404: bool = False,
    ) -> Optional[requests.Response]:
        """Send a GET request and handle common HTTP issues."""
        try:
            response = self.session.get(url)
        except requests.RequestException as exc:
            logger.error('Network error: %s', exc)
            time.sleep(sleep_time)
            return None

        if response.status_code == 401:
            raise Exception('Unauthorized: Invalid credentials')
        if response.status_code == 429:
            logger.warning('Rate limit exceeded. Sleeping for 15 minutes.')
            time.sleep(905)
            return None
        if response.status_code == 404:
            logger.info('No results for current window (404).')
            if raise_on_404:
                raise NoResultsError('HTTP 404: No results found')
            return None
        if response.status_code != 200:
            logger.error('Failed to fetch data. Status code: %s', response.status_code)
            logger.error('Response content: %s', response.content)
            return None

        return response

    @staticmethod
    def _extract_entries(response_json: Dict[str, Any]) -> tuple[list, Optional[str]]:
        """Extract timeline entries and cursor from the API response."""
        try:
            if 'data' not in response_json:
                return [], None

            search_data = response_json['data']
            if 'search_by_raw_query' not in search_data:
                timeline_data = search_data.get('search_timeline', {})
            else:
                timeline_data = search_data['search_by_raw_query'].get('search_timeline', {})

            instructions = timeline_data.get('timeline', {}).get('instructions', [])
        except (KeyError, TypeError):
            return [], None

        if not instructions:
            return [], None

        cursor = None
        last_instruction = instructions[-1]
        if last_instruction.get('type') == 'TimelineReplaceEntry':
            content = last_instruction.get('entry', {}).get('content', {})
            if content.get('cursorType') == 'Bottom':
                cursor = content.get('value')

        entries = instructions[0].get('entries', [])
        return entries, cursor

    @staticmethod
    def _shift_one_day_back(
        query_idx: int,
        current_query: Dict[str, Any],
        current_dates: Dict[int, Dict[str, datetime]],
        min_dates: Dict[int, Optional[datetime]],
        queries: list[Dict[str, Any]],
        encoded_queries: Dict[int, str],
    ) -> bool:
        """Move query window one day back.

        Returns ``False`` if the minimum date boundary is exceeded.
        """
        current_dates[query_idx]['until'] = current_dates[query_idx]['since']
        current_dates[query_idx]['since'] = (
            current_dates[query_idx]['until'] - timedelta(days=1)
        )

        query_min_date = min_dates[query_idx]
        if query_min_date and current_dates[query_idx]['since'] < query_min_date:
            return False

        query_copy = current_query.copy()
        query_copy['until'] = current_dates[query_idx]['until'].strftime('%Y-%m-%d')
        query_copy['since'] = current_dates[query_idx]['since'].strftime('%Y-%m-%d')
        queries[query_idx] = query_copy
        encoded_queries[query_idx] = Corvx._encode_query(query_copy)
        return True

    @staticmethod
    def _check_no_results(new_posts: int) -> None:
        """Raise :class:`NoResultsError` if no posts were found."""
        if new_posts == 0:
            raise NoResultsError('No posts found for query')

    def search(
        self,
        query: Union[Dict[str, Any], list[Dict[str, Any]], str, list[str]],
        deep: bool = False,
        fast: bool = False,
        limit: Optional[int] = None,
        sleep_time: float = 20,
    ) -> Generator[Dict[str, Any], None, None]:
        """Search posts matching the given query.

        Args:
            query: Query definition or list of queries. Each query can be a
                raw string or a dictionary following the advanced format.
            deep: If ``True`` paginate backwards in time until no results are
                left.
            fast: When combined with ``deep`` stop searching a query as soon as
                a cursor repeats.
            limit: Maximum number of posts to yield. ``None`` means unlimited.
            sleep_time: Delay between requests to avoid rate limits.

        Yields:
            Dictionaries representing tweets. Each tweet includes a
            ``raw_query`` field with the query string used to fetch it.
        """
        # Convert single query to list
        if not isinstance(query, list):
            query = [query]

        # Ensure all queries are dictionaries
        queries = [
            (query_obj if isinstance(query_obj, dict)
             else {'fields': [{'items': [query_obj]}]})
            for query_obj in query
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

        # Initialize active queries set
        active_queries = set(range(len(queries)))

        # For deep search without fast mode, initialize date boundaries for each query
        current_dates = {}
        min_dates = {}
        if deep and not fast:
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

                # Initialize dates even if we might skip this query
                current_dates[query_idx] = {
                    'until': current_until,
                    'since': current_since,
                }
                min_dates[query_idx] = min_date

                # Skip this query if we're already past the minimum date
                if min_date and current_since < min_date:
                    active_queries.discard(query_idx)
                    continue

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

                    if fast:
                        # In fast mode, if cursor repeats, we're done 
                        # with this query
                        active_queries.remove(query_idx)
                        continue

                    # Move to previous day if we got new posts
                    if new_posts_in_iteration[query_idx] > 0:
                        consecutive_empty_days[query_idx] = 0
                        if not self._shift_one_day_back(
                            query_idx,
                            current_query,
                            current_dates,
                            min_dates,
                            queries,
                            encoded_queries,
                        ):
                            active_queries.remove(query_idx)
                            continue
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
                    if not self._shift_one_day_back(
                        query_idx,
                        current_query,
                        current_dates,
                        min_dates,
                        queries,
                        encoded_queries,
                    ):
                        active_queries.remove(query_idx)
                        continue
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
                response = self._make_request(
                    url,
                    sleep_time,
                    raise_on_404=not deep,
                )
                if response is None:
                    if deep:
                        consecutive_empty_days[query_idx] += 1
                        if consecutive_empty_days[query_idx] >= 30:
                            active_queries.remove(query_idx)
                            continue
                        if not self._shift_one_day_back(
                            query_idx,
                            current_query,
                            current_dates,
                            min_dates,
                            queries,
                            encoded_queries,
                        ):
                            active_queries.remove(query_idx)
                            continue
                        encoded_query = encoded_queries[query_idx]
                        new_posts_in_iteration[query_idx] = 0
                        cursors[query_idx] = None
                        previous_cursors[query_idx] = None
                    else:
                        active_queries.remove(query_idx)
                    continue
                last_api_call = time.time()

                try:
                    response_json = response.json()
                except ValueError as exc:
                    logger.error('Invalid JSON response: %s', exc)
                    time.sleep(sleep_time)
                    continue

                entries, bottom_cursor = self._extract_entries(response_json)
                if bottom_cursor:
                    cursors[query_idx] = bottom_cursor

                if not entries:
                    if not deep:
                        self._check_no_results(posts_yielded)
                        active_queries.remove(query_idx)
                        continue

                    if fast:
                        active_queries.remove(query_idx)
                        continue

                    consecutive_empty_days[query_idx] += 1
                    if consecutive_empty_days[query_idx] >= 30:
                        active_queries.remove(query_idx)
                        continue

                    if not self._shift_one_day_back(
                        query_idx,
                        current_query,
                        current_dates,
                        min_dates,
                        queries,
                        encoded_queries,
                    ):
                        active_queries.remove(query_idx)
                        continue
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
                    # Include the raw search query used to retrieve this tweet
                    tweet['raw_query'] = encoded_query

                    yield tweet
                    posts_yielded += 1

                    if limit is not None and posts_yielded >= limit:
                        return

            if not new_posts_found and not deep:
                if posts_yielded == 0:
                    self._check_no_results(posts_yielded)
                return

            if limit is not None and posts_yielded >= limit:
                return

    def stream(
        self,
        query: Union[Dict[str, Any], list[Dict[str, Any]], str, list[str]],
        **kwargs,
    ) -> Generator[Dict[str, Any], None, None]:
        """Continuously yield new posts matching the query."""
        sleep_time = kwargs.get('sleep_time', 20)
        known_posts = CircularOrderedSet(100)
        while True:
            try:
                for post in self.search(query=query, **kwargs):
                    if post['id'] not in known_posts:
                        known_posts.add(post['id'])
                        yield post
            except NoResultsError:
                time.sleep(sleep_time)
            except Exception as e:
                logger.error('Error during post search: {}'.format(str(e)))
                time.sleep(sleep_time)
            else:
                time.sleep(sleep_time)
