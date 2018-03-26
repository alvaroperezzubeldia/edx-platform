"""
Test user retirement methods
TODO: When the hasher is working actually test it here with multiple salts
"""
from django.conf import settings
from django.contrib.auth.models import User
import pytest

from student.models import (
    get_all_retired_usernames_by_username,
    get_potentially_retired_user_by_username_and_hash,
    get_retired_username_by_username
)
from student.tests.factories import UserFactory


# Tell pytest it's ok to user the Django db
pytestmark = pytest.mark.django_db

RETIRED_USERNAME_PREFIX = settings.RETIRED_USERNAME_FMT.format("")

def test_get_retired_username():
    """
    Basic testing of getting retired usernames. The hasher is opaque
    to us, we just care that it's succeeding and using our format.
    """
    user = UserFactory()
    hashed_username = get_retired_username_by_username(user.username)
    assert hashed_username.startswith(RETIRED_USERNAME_PREFIX)
    assert len(hashed_username) > len(RETIRED_USERNAME_PREFIX)


def test_get_all_retired_usernames_by_username():
    """
    Placeholder test to get coverage on this while we wait for the
    hasher implementation.
    """
    user = UserFactory()
    hashed_usernames = list(get_all_retired_usernames_by_username(user.username))
    assert len(hashed_usernames) == len(settings.RETIRED_USERNAME_SALTS)
    assert hashed_usernames[0].startswith(RETIRED_USERNAME_PREFIX)
    assert len(hashed_usernames[0]) > len(RETIRED_USERNAME_PREFIX)


def test_get_potentially_retired_user_username_match():
    user = UserFactory()
    hashed_username = get_retired_username_by_username(user.username)
    assert get_potentially_retired_user_by_username_and_hash(user.username, hashed_username) == user


def test_get_potentially_retired_user_hashed_match():
    user = UserFactory()
    orig_username = user.username
    hashed_username = get_retired_username_by_username(orig_username)

    # Fake username retirement
    user.username = hashed_username
    user.save()

    assert get_potentially_retired_user_by_username_and_hash(orig_username, hashed_username) == user


def test_get_potentially_retired_user_does_not_exist():
    fake_username = "fake username"
    hashed_username = get_retired_username_by_username(fake_username)

    with pytest.raises(User.DoesNotExist):
        get_potentially_retired_user_by_username_and_hash(fake_username, hashed_username)


def test_get_potentially_retired_user_bad_hash():
    fake_username = "fake username"

    with pytest.raises(Exception):
        get_potentially_retired_user_by_username_and_hash(fake_username, "bad hash")
