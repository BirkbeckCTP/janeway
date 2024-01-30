__copyright__ = "Copyright 2023 Birkbeck, University of London"
__author__ = "Open Library of Humanities"
__license__ = "AGPL v3"
__maintainer__ = "Open Library of Humanities"

import os
import json
import glob
import json
import time
import requests
from typing import Tuple, List, Dict
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile

from cms import models as models
from journal import models as journal_models
from press import models as press_models
from repository import models as repository_models
from utils import setting_handler
from utils.function_cache import cache
from utils.logger import get_logger

logger = get_logger(__name__)

SITE_SEARCH_PATH = os.path.join(
    settings.MEDIA_ROOT,
    'press',
    settings.SITE_SEARCH_DIR,
)


def add_search_index_document(
    docs: List[Dict],
    url: str,
    name: str,
    text: str,
) -> List[Dict]:
    """
    Adds the data for a part or page to the search index
    """
    data = {}
    data['id'] = len(docs)
    data['url'] = url
    data['name'] = name
    data['text'] = text
    docs.append(data)
    return docs


def gobble_sibling_text(
    sibling: Tag | NavigableString,
    original_part: Tag | NavigableString,
) -> str:
    """
    Recursively collects a series of parallel elements for
    indexing together, stopping before another heading
    """

    # Handle no sibling
    if not sibling:
        return ''

    # Handle another heading
    if sibling.name == original_part.name:
        return ''
    if isinstance(sibling, Tag) and sibling.find(original_part.name):
        return ''

    # Recursively get sibling text
    if isinstance(sibling, NavigableString):
        sibling_text = sibling.strip()
    else:
        sibling_text = sibling.get_text().strip()
    next_sibling_text = gobble_sibling_text(
        sibling.next_sibling,
        original_part
    )

    # Decompose
    if isinstance(sibling, NavigableString):
        sibling.replace_with('')
    else:
        sibling.decompose()

    gobbled_text = sibling_text + ' ' + next_sibling_text
    return gobbled_text.strip()


def get_text_for_parent(
    parent: Tag | NavigableString,
    original_part: Tag | NavigableString,
) -> str:
    if not parent:
        return ''

    text = gobble_sibling_text(parent.next_sibling, original_part)
    if len(text.strip()) > len(original_part.get_text().strip()):
        return text
    else:
        return get_text_for_parent(parent.parent, original_part)


def get_text_for_header(part: Tag | NavigableString) -> str:
    """
    Gets the sibling text or parent text
    when given an h2, h3, or h4
    """

    # Try gobbling first
    text = gobble_sibling_text(part.next_sibling, part)
    if len(text.strip()) > 0:
        return text

    # Otherwise go to parent
    return get_text_for_parent(part.parent, part)


def add_part_as_doc(
    docs: List[Dict],
    part_url: str,
    part_name: str,
    part_text: str,
) -> List[Dict]:
    if not part_name or not part_text:
        # HTML tree with id has no heading
        # or no text content
        return docs
    return add_search_index_document(docs, part_url, part_name, part_text)


def add_searchable_page_parts(
        docs: List[Dict],
        url: str,
        body: Tag,
        headings: List | None = None,
    ) -> List[Dict]:
    if not headings:
        headings = ['h4', 'h3', 'h2']

    for h in headings:
        for part in body.find_all(h, id=True):
            if not part:
                continue
            part_id = part.get('id', '')
            if part_id:
                part_url = urljoin(url, '#' + part_id)
            else:
                part_url = remove_fragment(url)
            part_name = part.get_text().strip()
            part_text = get_text_for_header(part)
            docs = add_part_as_doc(docs, part_url, part_name, part_text)
            part.decompose()
    return docs


def get_page(
    url: str,
    fetched_urls: set[str]
) -> Tuple[BeautifulSoup | None, set[str]]:
    time.sleep(.1)
    try:
        fetched_urls.add(url)
        headers = {
            'Accept': 'text/html; charset=utf-8'
        }
        response = requests.get(url, headers=headers)
    except requests.exceptions.ConnectionError:
        logger.warn(f'Could not access {url}')
        logger.warn('Please run server to index site search')
        return None, fetched_urls

    if response.status_code != 200:
        return None, fetched_urls

    if 'text/html' not in response.headers['Content-Type']:
        return None, fetched_urls

    soup = BeautifulSoup(response.text, 'html.parser')
    return soup, fetched_urls


def get_name(html: BeautifulSoup) -> str:
    try:
        return html.find('h1').get_text().strip()
    except AttributeError:
        return html.title.get_text().strip()


def get_body(html: BeautifulSoup) -> Tag | None:
    body = html.find('body')
    if not isinstance(body, Tag):
        return
    for non_content_selector in ['script', '.djdt-hidden']:
        for element in body.select(non_content_selector):
            element.decompose()
    for element in body.find_all(text=lambda text: isinstance(text, Comment)):
        element.extract()
    return body


@cache(900)
def get_base(press: press_models.Press) -> str:
    return press.site_url()


@cache(900)
def excluded_urls() -> List[str]:
    return [
        journal.site_url() for journal in journal_models.Journal.objects.all()
    ] + [
        repo.site_url() for repo in repository_models.Repository.objects.all()
    ]


def url_in_scope(press: press_models.Press, deeper_url: str) -> bool:
    base = get_base(press)
    if urlparse(deeper_url).hostname != urlparse(base).hostname:
        return False
    for excluded_url in excluded_urls():
        if excluded_url in deeper_url:
            return False
    return True


def remove_fragment(url: str) -> str:
    fragment = urlparse(url).fragment
    return url.replace('#' + fragment, '')


def normalize_url(url: str) -> str:
    url = remove_fragment(url)
    if url.endswith('/'):
        url = url[:-1]
    return url


def url_is_new(fetched_urls: set[str], deeper_url: str) -> bool:
    if deeper_url in fetched_urls:
        return False
    for fetched_url in fetched_urls:
        if normalize_url(fetched_url) == normalize_url(deeper_url):
            return False
    return True


def decompose_non_content_page_regions(body: Tag) -> None:
    for non_content_selector in ['header', 'footer', 'h1']:
        for element in body.select(non_content_selector):
            element.decompose()


def add_searchable_page(
        press: press_models.Press,
        docs: List[Dict],
        fetched_urls: set[str],
        url: str,
    ) -> Tuple[List[Dict], set[str]]:
    html, fetched_urls = get_page(url, fetched_urls)
    if not html:
        return docs, fetched_urls

    body = get_body(html)
    if not body:
        return docs, fetched_urls

    for anchor in body.find_all('a'):
        href = anchor.get('href', '').strip()
        deeper_url = urljoin(url, href)
        if url_in_scope(press, deeper_url) and url_is_new(fetched_urls, deeper_url):
            docs, fetched_urls = add_searchable_page(
                press,
                docs,
                fetched_urls,
                deeper_url
            )

    name = get_name(html)
    decompose_non_content_page_regions(body)

    docs = add_searchable_page_parts(docs, url, body)
    docs = add_search_index_document(docs, url, name, body.get_text())
    return docs, fetched_urls


def get_press_site_search_data(press: press_models.Press) -> List[Dict]:
    """
    Generates data for press-level site search index
    to be used by MiniSearch
    """
    docs = []
    fetched_urls = set()
    base = get_base(press)
    docs, fetched_urls = add_searchable_page(press, docs, fetched_urls, base)

    if not len(docs) > 0:
        logger.error('Search data store is empty')

    return docs


def get_search_docs_filename(press):
    return os.path.join(
        settings.SITE_SEARCH_DIR,
        f'_press_{ press.pk }_documents.json'
    )


def get_search_docs_filepath(press):
    return os.path.join(
        SITE_SEARCH_PATH,
        f'_press_{ press.pk }_documents.json'
    )


def update_search_data(press):
    docs_filename = get_search_docs_filename(press)
    docs_file, created = models.MediaFile.objects.get_or_create(
        label=docs_filename
    )
    if not created:
        docs_file.unlink()

    documents = get_press_site_search_data(press)
    docs_json = json.dumps(documents, separators=(',', ':'))

    content_file = ContentFile(docs_json.encode('utf-8'))
    docs_file.file.save(docs_filename, content_file, save=True)
    return docs_file


def delete_search_data(press):
    path = get_search_docs_filepath(press)
    files_deleted = []
    if os.path.exists(path):
        os.unlink(path)
        files_deleted.append(path)
    if settings.IN_TEST_RUNNER:
        if os.listdir(SITE_SEARCH_PATH):
            logger.warning(
                f'Left-over test files: {os.listdir(SITE_SEARCH_PATH)}'
            )
        else:
            os.rmdir(SITE_SEARCH_PATH)

    return files_deleted


@cache(900)
def get_search_data_url(press):
    docs_filename = get_search_docs_filename(press)
    try:
        return models.MediaFile.objects.get(label=docs_filename).file.url
    except models.MediaFile.DoesNotExist:
        raise ImproperlyConfigured(
            'Site search indexing is turned on, but there is no data file. '
            'Set settings.SITE_SEARCH_INDEXING_FREQUENCY to None to turn off, '
            'or run manage.py generate_site_search_data.'
        )


def get_custom_templates_folder(journal):
    setting = setting_handler.get_setting(
        'general',
        'custom_cms_templates',
        journal,
        default=False,
    )
    return setting.processed_value if setting else ''


def get_custom_templates_path(journal, press):
    if journal:
        theme = setting_handler.get_setting(
            'general',
            'journal_theme',
            journal,
        ).processed_value
    elif press and press.theme:
        theme = press.theme
    else:
        return ''

    folder = get_custom_templates_folder(journal)
    if not folder:
        return ''

    return os.path.join(settings.BASE_DIR, 'themes', theme, 'templates', folder)


def get_custom_templates(journal, press):

    templates_folder = get_custom_templates_folder(journal)
    templates_path = get_custom_templates_path(journal, press)
    if not templates_folder or not templates_path:
        return []

    custom_templates = [('','-----')]
    for filepath in sorted(glob.glob(os.path.join(templates_path, '*.html'))):
        choice = (
            os.path.join(templates_folder, os.path.basename(filepath)),
            os.path.basename(filepath),
        )
        custom_templates.append(choice)
    return custom_templates
