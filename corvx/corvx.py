import json
import time
import urllib.parse
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Generator, Union, Tuple, List, Set
from urllib.parse import urlparse

import requests
import os
import bs4
from x_client_transaction.utils import generate_headers, get_ondemand_file_url
from x_client_transaction import ClientTransaction

from .structures import CircularOrderedSet


# Constants
X_CLIENT_TOKEN = (
    'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs'
    '%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'
)
SEARCH_BASE_URL = (
    'https://x.com/i/api/graphql/'
    'Tp1sewRU1AsZpBWhqCZicQ/SearchTimeline'
)
HOME_PAGE_URL = 'https://x.com'
MAX_CONSECUTIVE_EMPTY_DAYS = 30
DEFAULT_COUNT = 20
DEFAULT_SLEEP_TIME = 20
RATE_LIMIT_SLEEP_TIME = 905  # 15 minutes + 5 seconds
KNOWN_POSTS_CACHE_SIZE = 100


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


# Global ClientTransaction setup - initialized once when needed
_client_transaction = None
_home_page_response = None
_ondemand_file_response = None


def _setup_client_transaction() -> Optional[ClientTransaction]:
    """Setup ClientTransaction using direct requests approach."""
    global _client_transaction, _home_page_response, _ondemand_file_response

    if _client_transaction is not None:
        return _client_transaction

    try:
        # Get home page and ondemand file
        session = requests.Session()
        session.headers = generate_headers()

        home_page = session.get(url=HOME_PAGE_URL)
        _home_page_response = bs4.BeautifulSoup(
            home_page.content,
            'html.parser',
        )

        ondemand_file_url = get_ondemand_file_url(
            response=_home_page_response,
        )
        ondemand_file = session.get(url=ondemand_file_url)
        _ondemand_file_response = bs4.BeautifulSoup(
            ondemand_file.content,
            'html.parser',
        )

        _client_transaction = ClientTransaction(
            home_page_response=_home_page_response,
            ondemand_file_response=_ondemand_file_response,
        )

        session.close()
        logger.debug('ClientTransaction setup completed')
        return _client_transaction

    except Exception as e:
        logger.warning('ClientTransaction setup failed: {0}'.format(e))
        return None


def _generate_transaction_id(url: str, method: str = 'GET') -> str:
    """Generate X-Client-Transaction-Id using XClientTransaction library."""
    ct = _setup_client_transaction()
    if ct is None:
        return ''

    try:
        path = urlparse(url=url).path
        return ct.generate_transaction_id(method=method, path=path)
    except Exception as e:
        logger.warning('Transaction ID generation failed: {0}'.format(e))
        return ''


class QueryEncoder:
    """Handles encoding of search queries."""

    @staticmethod
    def encode_query(query: Dict[str, Any]) -> str:
        """Encode a query dictionary into a search string."""
        encoded_query = ''
        since = query.get('since')
        until = query.get('until')
        near = query.get('near')
        lang = query.get('lang')
        fields = query.get('fields', [])

        for field in fields:
            marginal_query = QueryEncoder._encode_field(field)
            match = field.get('match')

            if match == 'any':
                marginal_query = ' OR '.join(marginal_query.split())
                encoded_query += ' ({0})'.format(marginal_query)
            elif match == 'none':
                marginal_query = '-{0}'.format(
                    ' -'.join(marginal_query.split()),
                )
                encoded_query += ' {0}'.format(marginal_query)
            else:
                encoded_query += ' {0}'.format(marginal_query)

        encoded_query = QueryEncoder._add_date_filters(
            encoded_query,
            since,
            until,
        )
        encoded_query = QueryEncoder._add_location_filter(encoded_query, near)
        encoded_query = encoded_query.strip()
        encoded_query = QueryEncoder._add_language_filter(encoded_query, lang)

        QueryEncoder._log_test_url(encoded_query)
        return encoded_query

    @staticmethod
    def _encode_field(field: Dict[str, Any]) -> str:
        """Encode a single field from the query."""
        target = field.get('target')
        items = field['items']
        exact = field.get('exact', False)

        if exact:
            return '"{0}"'.format('" "'.join(items))

        if target == 'from':
            return 'from:{0}'.format(' from:'.join(items))
        elif target == 'to':
            return 'to:{0}'.format(' to:'.join(items))
        elif target == 'hashtag':
            return '#{0}'.format(' #'.join(items))
        elif target == 'mention':
            return '@{0}'.format(' @'.join(items))
        else:
            return ' '.join(items)

    @staticmethod
    def _add_date_filters(
        encoded_query: str,
        since: Optional[str],
        until: Optional[str],
    ) -> str:
        """Add date filters to the encoded query."""
        if since:
            encoded_query += ' since:{0}'.format(since)
        if until:
            encoded_query += ' until:{0}'.format(until)
        return encoded_query

    @staticmethod
    def _add_location_filter(
        encoded_query: str,
        near: Optional[List[str]],
    ) -> str:
        """Add location filter to the encoded query."""
        if near:
            encoded_query += ' near:"{0}" within:{1}mi'.format(
                near[0],
                near[1],
            )
        return encoded_query

    @staticmethod
    def _add_language_filter(
        encoded_query: str,
        lang: Optional[str],
    ) -> str:
        """Add language filter to the encoded query."""
        if lang:
            encoded_query += ' lang:{0}'.format(lang)
        return encoded_query

    @staticmethod
    def _log_test_url(encoded_query: str) -> None:
        """Log the test URL for debugging purposes."""
        test_url = 'https://twitter.com/search?q={0}'.format(
            urllib.parse.quote(encoded_query).replace('%20', '+'),
        )
        logger.debug('[Test URL] {0}&src=typed_query&f=live'.format(test_url))


class URLBuilder:
    """Handles building API URLs for requests."""

    @staticmethod
    def build_search_url(query: str, cursor: Optional[str] = None) -> str:
        """Build the search timeline URL with proper parameters."""
        payload = URLBuilder._create_payload(query, cursor)
        url = SEARCH_BASE_URL

        variables_param = urllib.parse.quote(
            json.dumps(payload['variables'], separators=(',', ':')),
        )
        url += '?variables={0}'.format(variables_param)

        features_param = urllib.parse.quote(
            json.dumps(payload['features'], separators=(',', ':')),
        )
        url += '&features={0}'.format(features_param)

        field_toggles_param = urllib.parse.quote(
            json.dumps(payload['fieldToggles'], separators=(',', ':')),
        )
        url += '&fieldToggles={0}'.format(field_toggles_param)

        return url

    @staticmethod
    def _create_payload(query: str, cursor: Optional[str]) -> Dict[str, Any]:
        """Create the payload for the API request."""
        payload = {
            'variables': {
                'rawQuery': query,
                'count': DEFAULT_COUNT,
                'querySource': 'typed_query',
                'product': 'Latest',
            },
            'features': URLBuilder._get_features(),
            'fieldToggles': {
                'withArticleRichContentState': False,
            },
        }

        if cursor is not None:
            payload['variables']['cursor'] = cursor

        return payload

    @staticmethod
    def _get_features() -> Dict[str, bool]:
        """Get the features configuration for API requests."""
        return {
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
            'responsive_web_grok_analyze_button_fetch_trends_'
            'enabled': False,
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
        }


class ResponseProcessor:
    """Handles processing of API responses."""

    @staticmethod
    def extract_entries(
        response_json: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Extract timeline entries and cursor from the API response."""
        try:
            if 'data' not in response_json:
                return [], None

            search_data = response_json['data']
            timeline_data = ResponseProcessor._get_timeline_data(search_data)
            timeline = timeline_data.get('timeline', {})
            instructions = timeline.get('instructions', [])
        except (KeyError, TypeError):
            return [], None

        if not instructions:
            return [], None

        cursor = ResponseProcessor._extract_cursor(instructions)
        entries = instructions[0].get('entries', [])
        return entries, cursor

    @staticmethod
    def _get_timeline_data(search_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract timeline data from search response."""
        if 'search_by_raw_query' not in search_data:
            return search_data.get('search_timeline', {})
        else:
            search_by_raw_query = search_data['search_by_raw_query']
            return search_by_raw_query.get('search_timeline', {})

    @staticmethod
    def _extract_cursor(instructions: List[Dict[str, Any]]) -> Optional[str]:
        """Extract cursor from instructions."""
        last_instruction = instructions[-1]
        if last_instruction.get('type') == 'TimelineReplaceEntry':
            content = last_instruction.get('entry', {}).get('content', {})
            if content.get('cursorType') == 'Bottom':
                return content.get('value')
        return None

    @staticmethod
    def process_tweet_entry(
        entry: Dict[str, Any],
        encoded_query: str,
    ) -> Optional[Dict[str, Any]]:
        """Process a single tweet entry from the timeline."""
        try:
            data = (entry['content']['itemContent']
                    ['tweet_results']['result'])
        except KeyError:
            return None

        if 'legacy' not in data:
            data = data['tweet']

        tweet = data['legacy']
        processed_tweet = {
            'id': data['rest_id'],
            'created_at': int(datetime.strptime(
                tweet['created_at'],
                '%a %b %d %H:%M:%S %z %Y',
            ).timestamp()),
            'full_text': tweet['full_text'],
            'retweet_count': tweet['retweet_count'],
            'favorite_count': tweet['favorite_count'],
        }

        user_info = ResponseProcessor._extract_user_info(data)
        processed_tweet.update(user_info)

        tweet_url = 'https://twitter.com/{0}/status/{1}'.format(
            processed_tweet['screen_name'],
            processed_tweet['id'],
        )
        processed_tweet['url'] = tweet_url
        processed_tweet['raw_query'] = encoded_query

        return processed_tweet

    @staticmethod
    def _extract_user_info(data: Dict[str, Any]) -> Dict[str, str]:
        """Extract user information from tweet data."""
        user = data['core']['user_results']['result']
        try:
            return {
                'name': user['core']['name'],
                'screen_name': user['core']['screen_name'],
            }
        except KeyError as e:
            logger.debug('Missing user data field: %s', e)
            logger.debug('User data structure: %s', user)
            # Try alternative structure or provide defaults
            core_user = user.get('core', {})
            return {
                'name': core_user.get('name', 'Unknown'),
                'screen_name': core_user.get(
                    'screen_name',
                    'unknown',
                ),
            }


class DateManager:
    """Handles date management for deep search functionality."""

    @staticmethod
    def initialize_dates(
        queries: List[Dict[str, Any]],
    ) -> Tuple[Dict[int, Dict[str, datetime]], Dict[int, Optional[datetime]]]:
        """Initialize date ranges for deep search."""
        current_dates = {}
        min_dates = {}

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

            current_dates[query_idx] = {
                'until': current_until,
                'since': current_since,
            }
            min_dates[query_idx] = min_date

        return current_dates, min_dates

    @staticmethod
    def shift_one_day_back(
        query_idx: int,
        current_query: Dict[str, Any],
        current_dates: Dict[int, Dict[str, datetime]],
        min_dates: Dict[int, Optional[datetime]],
        queries: List[Dict[str, Any]],
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
        query_since = current_dates[query_idx]['since']
        if query_min_date and query_since < query_min_date:
            return False

        query_copy = current_query.copy()
        until_str = current_dates[query_idx]['until'].strftime('%Y-%m-%d')
        query_copy['until'] = until_str
        since_str = current_dates[query_idx]['since'].strftime('%Y-%m-%d')
        query_copy['since'] = since_str
        queries[query_idx] = query_copy
        encoded_queries[query_idx] = QueryEncoder.encode_query(query_copy)
        return True

    @staticmethod
    def update_query_with_dates(
        query_idx: int,
        current_query: Dict[str, Any],
        current_dates: Dict[int, Dict[str, datetime]],
        queries: List[Dict[str, Any]],
    ) -> None:
        """Update query with current date range."""
        query_copy = current_query.copy()
        until_str = current_dates[query_idx]['until'].strftime('%Y-%m-%d')
        query_copy['until'] = until_str
        since_str = current_dates[query_idx]['since'].strftime('%Y-%m-%d')
        query_copy['since'] = since_str
        queries[query_idx] = query_copy


class Corvx:
    X_CLIENT_TOKEN = X_CLIENT_TOKEN
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
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': 'Bearer {0}'.format(self.X_CLIENT_TOKEN),
            'Content-Type': 'application/json',
            'Cookie': 'auth_token={0}; ct0={1}'.format(
                self.auth_token,
                self.csrf_token,
            ),
            'X-Csrf-Token': self.csrf_token,
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _generate_transaction_id(self, url: str, method: str = 'GET') -> str:
        """Generate X-Client-Transaction-Id for the given URL and method."""
        return _generate_transaction_id(url, method)

    def get_url(self, query: str, cursor: Optional[str] = None) -> str:
        """Get the URL for a search query with optional cursor."""
        return URLBuilder.build_search_url(query, cursor)

    def _make_request(
        self,
        url: str,
        sleep_time: float,
        raise_on_404: bool = False,
    ) -> Optional[requests.Response]:
        """Send a GET request and handle common HTTP issues."""
        logger.debug('Making request to: %s', url)

        # Generate fresh transaction ID for this request
        transaction_id = _generate_transaction_id(url)
        if transaction_id:
            self.session.headers['X-Client-Transaction-Id'] = transaction_id

        logger.debug('Request headers: %s', dict(self.session.headers))

        try:
            response = self.session.get(url)
        except requests.RequestException as exc:
            logger.error('Network error: %s', exc)
            time.sleep(sleep_time)
            return None

        return self._handle_response(response, sleep_time, raise_on_404)

    def _handle_response(
        self,
        response: requests.Response,
        sleep_time: float,
        raise_on_404: bool,
    ) -> Optional[requests.Response]:
        """Handle HTTP response and errors."""
        logger.debug('Response status: %s', response.status_code)

        if response.status_code != 200:
            logger.debug('Response headers: %s', dict(response.headers))
            content_preview = response.content[:500]
            logger.debug('Response content preview: %s', content_preview)

        if response.status_code == 401:
            raise Exception('Unauthorized: Invalid credentials')
        if response.status_code == 429:
            logger.warning('Rate limit exceeded. Sleeping for 15 minutes.')
            time.sleep(RATE_LIMIT_SLEEP_TIME)
            return None
        if response.status_code == 404:
            logger.info('No results for current window (404).')
            if raise_on_404:
                raise NoResultsError('HTTP 404: No results found')
            return None
        if response.status_code != 200:
            status_code = response.status_code
            logger.error('Failed to fetch data. Status code: %s', status_code)
            logger.error('Response content: %s', response.content)
            return None

        return response

    @staticmethod
    def _check_no_results(new_posts: int) -> None:
        """Raise :class:`NoResultsError` if no posts were found."""
        if new_posts == 0:
            raise NoResultsError('No posts found for query')

    def _normalize_queries(
        self,
        query: Union[Dict[str, Any], List[Dict[str, Any]], str, List[str]],
    ) -> List[Dict[str, Any]]:
        """Normalize input queries to a list of dictionaries."""
        # Convert single query to list
        if not isinstance(query, list):
            query = [query]

        # Ensure all queries are dictionaries
        return [
            (query_obj if isinstance(query_obj, dict)
             else {'fields': [{'items': [query_obj]}]})
            for query_obj in query
        ]

    def _setup_deep_search(
        self,
        queries: List[Dict[str, Any]],
        deep: bool,
        fast: bool,
    ) -> Tuple[
        Set[int],
        Dict[int, Dict[str, datetime]],
        Dict[int, Optional[datetime]],
    ]:
        """Setup for deep search mode."""
        active_queries = set(range(len(queries)))
        current_dates = {}
        min_dates = {}

        if deep and not fast:
            current_dates, min_dates = DateManager.initialize_dates(queries)

            for query_idx, current_query in enumerate(queries):
                # Skip this query if we're already past the minimum date
                min_date = min_dates[query_idx]
                current_since = current_dates[query_idx]['since']
                if min_date and current_since < min_date:
                    active_queries.discard(query_idx)
                    continue

                # Update query with date range
                DateManager.update_query_with_dates(
                    query_idx,
                    current_query,
                    current_dates,
                    queries,
                )

        return active_queries, current_dates, min_dates

    def _process_single_query(
        self,
        query_idx: int,
        queries: List[Dict[str, Any]],
        cursors: Dict[int, Optional[str]],
        previous_cursors: Dict[int, Optional[str]],
        encoded_queries: Dict[int, str],
        deep: bool,
        fast: bool,
        sleep_time: float,
        last_api_call: float,
        current_dates: Dict[int, Dict[str, datetime]],
        min_dates: Dict[int, Optional[datetime]],
        new_posts_in_iteration: Dict[int, int],
        consecutive_empty_days: Dict[int, int],
        active_queries: Set[int],
    ) -> Tuple[List[Dict[str, Any]], float, bool]:
        """Process a single query and return tweets found."""
        current_query = queries[query_idx]
        current_cursor = cursors[query_idx]
        prev_cursor = previous_cursors[query_idx]
        encoded_query = encoded_queries[query_idx]

        # Handle cursor repetition
        if current_cursor and prev_cursor == current_cursor:
            return self._handle_cursor_repetition(
                query_idx,
                deep,
                fast,
                current_query,
                current_dates,
                min_dates,
                queries,
                encoded_queries,
                new_posts_in_iteration,
                consecutive_empty_days,
                cursors,
                previous_cursors,
                active_queries,
            )

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

        last_api_call = time.time()

        if response is None:
            return self._handle_no_response(
                query_idx,
                deep,
                current_query,
                current_dates,
                min_dates,
                queries,
                encoded_queries,
                new_posts_in_iteration,
                consecutive_empty_days,
                cursors,
                previous_cursors,
                active_queries,
            )

        return self._process_response(
            response,
            query_idx,
            queries,
            cursors,
            encoded_queries,
            deep,
            fast,
            sleep_time,
            current_dates,
            min_dates,
            new_posts_in_iteration,
            consecutive_empty_days,
            active_queries,
        ), last_api_call, True

    def _handle_cursor_repetition(
        self,
        query_idx: int,
        deep: bool,
        fast: bool,
        current_query: Dict[str, Any],
        current_dates: Dict[int, Dict[str, datetime]],
        min_dates: Dict[int, Optional[datetime]],
        queries: List[Dict[str, Any]],
        encoded_queries: Dict[int, str],
        new_posts_in_iteration: Dict[int, int],
        consecutive_empty_days: Dict[int, int],
        cursors: Dict[int, Optional[str]],
        previous_cursors: Dict[int, Optional[str]],
        active_queries: Set[int],
    ) -> Tuple[List[Dict[str, Any]], float, bool]:
        """Handle case when cursor repeats."""
        if not deep:
            active_queries.remove(query_idx)
            return [], 0.0, False

        if fast:
            # In fast mode, if cursor repeats, we're done with this query
            active_queries.remove(query_idx)
            return [], 0.0, False

        # Move to previous day if we got new posts
        if new_posts_in_iteration[query_idx] > 0:
            consecutive_empty_days[query_idx] = 0
            if not DateManager.shift_one_day_back(
                query_idx,
                current_query,
                current_dates,
                min_dates,
                queries,
                encoded_queries,
            ):
                active_queries.remove(query_idx)
                return [], 0.0, False

            new_posts_in_iteration[query_idx] = 0
            cursors[query_idx] = None
            previous_cursors[query_idx] = None
            return [], 0.0, False

        # No new posts, count empty day
        consecutive_empty_days[query_idx] += 1
        if consecutive_empty_days[query_idx] >= MAX_CONSECUTIVE_EMPTY_DAYS:
            active_queries.remove(query_idx)
            return [], 0.0, False

        # Move to previous day
        if not DateManager.shift_one_day_back(
            query_idx,
            current_query,
            current_dates,
            min_dates,
            queries,
            encoded_queries,
        ):
            active_queries.remove(query_idx)
            return [], 0.0, False

        new_posts_in_iteration[query_idx] = 0
        cursors[query_idx] = None
        previous_cursors[query_idx] = None
        return [], 0.0, False

    def _handle_no_response(
        self,
        query_idx: int,
        deep: bool,
        current_query: Dict[str, Any],
        current_dates: Dict[int, Dict[str, datetime]],
        min_dates: Dict[int, Optional[datetime]],
        queries: List[Dict[str, Any]],
        encoded_queries: Dict[int, str],
        new_posts_in_iteration: Dict[int, int],
        consecutive_empty_days: Dict[int, int],
        cursors: Dict[int, Optional[str]],
        previous_cursors: Dict[int, Optional[str]],
        active_queries: Set[int],
    ) -> List[Dict[str, Any]]:
        """Handle case when no response is received."""
        if deep:
            consecutive_empty_days[query_idx] += 1
            if consecutive_empty_days[query_idx] >= MAX_CONSECUTIVE_EMPTY_DAYS:
                active_queries.remove(query_idx)
                return []

            if not DateManager.shift_one_day_back(
                query_idx,
                current_query,
                current_dates,
                min_dates,
                queries,
                encoded_queries,
            ):
                active_queries.remove(query_idx)
                return []

            new_posts_in_iteration[query_idx] = 0
            cursors[query_idx] = None
            previous_cursors[query_idx] = None
        else:
            active_queries.remove(query_idx)

        return []

    def _process_response(
        self,
        response: requests.Response,
        query_idx: int,
        queries: List[Dict[str, Any]],
        cursors: Dict[int, Optional[str]],
        encoded_queries: Dict[int, str],
        deep: bool,
        fast: bool,
        sleep_time: float,
        current_dates: Dict[int, Dict[str, datetime]],
        min_dates: Dict[int, Optional[datetime]],
        new_posts_in_iteration: Dict[int, int],
        consecutive_empty_days: Dict[int, int],
        active_queries: Set[int],
    ) -> List[Dict[str, Any]]:
        """Process API response and extract tweets."""
        try:
            response_json = response.json()
        except ValueError as exc:
            logger.error('Invalid JSON response: %s', exc)
            time.sleep(sleep_time)
            return []

        entries, bottom_cursor = ResponseProcessor.extract_entries(
            response_json,
        )
        if bottom_cursor:
            cursors[query_idx] = bottom_cursor

        if not entries:
            return self._handle_empty_entries(
                query_idx,
                deep,
                fast,
                queries,
                encoded_queries,
                current_dates,
                min_dates,
                new_posts_in_iteration,
                consecutive_empty_days,
                cursors,
                active_queries,
            )

        # Process entries and extract tweets
        tweets = []
        encoded_query = encoded_queries[query_idx]

        for entry in entries:
            tweet = ResponseProcessor.process_tweet_entry(entry, encoded_query)
            if tweet:
                tweets.append(tweet)
            else:
                # Try to extract cursor from entry
                try:
                    entry_content = entry['content']
                    if entry_content['entryType'] == 'TimelineTimelineCursor':
                        cursor_type = entry_content['cursorType']
                        if cursor_type.lower() == 'bottom':
                            cursors[query_idx] = entry_content['value']
                except KeyError as error:
                    logger.error('Error processing entry: {}'.format(error))
                    logger.debug('Entry details: {}'.format(entry))

        return tweets

    def _handle_empty_entries(
        self,
        query_idx: int,
        deep: bool,
        fast: bool,
        queries: List[Dict[str, Any]],
        encoded_queries: Dict[int, str],
        current_dates: Dict[int, Dict[str, datetime]],
        min_dates: Dict[int, Optional[datetime]],
        new_posts_in_iteration: Dict[int, int],
        consecutive_empty_days: Dict[int, int],
        cursors: Dict[int, Optional[str]],
        active_queries: Set[int],
    ) -> List[Dict[str, Any]]:
        """Handle case when no entries are found in response."""
        if not deep:
            active_queries.remove(query_idx)
            return []

        if fast:
            active_queries.remove(query_idx)
            return []

        consecutive_empty_days[query_idx] += 1
        if consecutive_empty_days[query_idx] >= MAX_CONSECUTIVE_EMPTY_DAYS:
            active_queries.remove(query_idx)
            return []

        current_query = queries[query_idx]
        if not DateManager.shift_one_day_back(
            query_idx,
            current_query,
            current_dates,
            min_dates,
            queries,
            encoded_queries,
        ):
            active_queries.remove(query_idx)
            return []

        new_posts_in_iteration[query_idx] = 0
        cursors[query_idx] = None
        return []

    def search(
        self,
        query: Union[Dict[str, Any], List[Dict[str, Any]], str, List[str]],
        deep: bool = False,
        fast: bool = False,
        limit: Optional[int] = None,
        sleep_time: float = DEFAULT_SLEEP_TIME,
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
        queries = self._normalize_queries(query)

        # Setup tracking variables
        last_api_call = 0.0
        known_posts = set()
        posts_yielded = 0
        new_posts_in_iteration = {
            query_idx: 0 for query_idx in range(len(queries))
        }
        consecutive_empty_days = {
            query_idx: 0 for query_idx in range(len(queries))
        }

        # Setup deep search if needed
        active_queries, current_dates, min_dates = self._setup_deep_search(
            queries,
            deep,
            fast,
        )

        cursors = {query_idx: None for query_idx in range(len(queries))}
        previous_cursors = {
            query_idx: None for query_idx in range(len(queries))
        }
        encoded_queries = {
            query_idx: QueryEncoder.encode_query(query_obj)
            for query_idx, query_obj in enumerate(queries)
        }

        while active_queries:
            new_posts_found = False

            # Process one page from each active query
            for query_idx in list(active_queries):
                tweets, last_api_call, should_continue = (
                    self._process_single_query(
                        query_idx,
                        queries,
                        cursors,
                        previous_cursors,
                        encoded_queries,
                        deep,
                        fast,
                        sleep_time,
                        last_api_call,
                        current_dates,
                        min_dates,
                        new_posts_in_iteration,
                        consecutive_empty_days,
                        active_queries,
                    )
                )

                if not should_continue:
                    continue

                # Yield new tweets
                for tweet in tweets:
                    if tweet['id'] in known_posts:
                        continue

                    known_posts.add(tweet['id'])
                    new_posts_found = True
                    new_posts_in_iteration[query_idx] += 1

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
        query: Union[Dict[str, Any], List[Dict[str, Any]], str, List[str]],
        **kwargs,
    ) -> Generator[Dict[str, Any], None, None]:
        """Continuously yield new posts matching the query."""
        sleep_time = kwargs.get('sleep_time', DEFAULT_SLEEP_TIME)
        known_posts = CircularOrderedSet(KNOWN_POSTS_CACHE_SIZE)

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
