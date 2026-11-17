import textwrap
import uuid

import pytest

import keyring.backend
import keyring.core
from keyring.compat import properties


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    path = tmp_path / 'keyringrc.cfg'
    monkeypatch.setattr(keyring.core, '_config_path', lambda: path)
    return path


def test_init_recommended(monkeypatch):
    """
    Test filtering of backends to recommended ones (#117, #423).
    """
    monkeypatch.setattr(keyring.core, 'set_keyring', lambda kr: None)
    keyring.core.init_backend(keyring.core.recommended)


def test_load_config_missing(caplog, config_path):
    assert keyring.core.load_config() is None
    assert not caplog.records


def test_load_empty_config(caplog, config_path):
    config_path.write_text("", encoding='utf-8')
    assert keyring.core.load_config() is None
    assert not caplog.records


fail_config = textwrap.dedent(
    """
    [backend]
    default-keyring = keyring.backends.fail.Keyring
    """
).lstrip()


def test_load_config_extant(caplog, config_path):
    config_path.write_text(fail_config, encoding='utf-8')
    assert keyring.core.load_config() is not None
    assert not caplog.records


class SchemeSelectableBackend(
    keyring.backend.SchemeSelectable, keyring.backend.KeyringBackend
):
    """Minimal concrete backend for exercising scheme injection."""

    @properties.classproperty
    def priority(cls):
        raise RuntimeError('test double is never viable')

    def get_password(self, service, username):
        return None

    def set_password(self, service, username, password):
        pass


@pytest.fixture
def win_vault():
    win = pytest.importorskip('keyring.backends.Windows')
    if not win.WinVaultKeyring.viable:
        pytest.skip('Needs Windows with pywin32')
    return win


class TestPersistInjection:
    """
    The persistence policy injected via with_properties must be honored
    by the Persistence data descriptor, identically to the direct
    assignment and environment variable channels.
    """

    def test_write_follows_injected_persist(self, win_vault, monkeypatch):
        written = []
        monkeypatch.setattr(
            win_vault.win32cred,
            'CredWrite',
            lambda credential, flags: written.append(credential),
        )
        service = f'keyring-test-{uuid.uuid4()}'

        base = win_vault.WinVaultKeyring()
        alt = base.with_properties(persist='local machine')
        alt.set_password(service, 'user', 'pass')
        base.set_password(f'{service}-default', 'user', 'pass')

        assert written[0]['Persist'] == win_vault.win32cred.CRED_PERSIST_LOCAL_MACHINE
        assert written[1]['Persist'] == win_vault.win32cred.CRED_PERSIST_ENTERPRISE

    def test_channels_read_back_consistently(self, win_vault, monkeypatch):
        expected = win_vault.win32cred.CRED_PERSIST_LOCAL_MACHINE
        assert expected != win_vault.win32cred.CRED_PERSIST_ENTERPRISE

        direct = win_vault.WinVaultKeyring()
        direct.persist = 'local machine'

        via_props = win_vault.WinVaultKeyring().with_properties(
            persist='local machine'
        )

        monkeypatch.setenv('KEYRING_PROPERTY_PERSIST', 'local machine')
        via_env = win_vault.WinVaultKeyring()

        assert direct.persist == expected
        assert via_props.persist == expected
        assert via_env.persist == expected


class TestSchemeInjection:
    """
    An invalid scheme must be rejected at injection time, whichever
    channel supplies it, not deferred to the first query.
    """

    def test_with_properties_invalid_scheme_raises(self):
        backend = SchemeSelectableBackend()
        with pytest.raises(ValueError, match='bogus'):
            backend.with_properties(scheme='bogus')

    def test_direct_assignment_invalid_scheme_raises(self):
        backend = SchemeSelectableBackend()
        with pytest.raises(ValueError, match='bogus'):
            backend.scheme = 'bogus'

    def test_env_invalid_scheme_raises(self, monkeypatch):
        monkeypatch.setenv('KEYRING_PROPERTY_SCHEME', 'bogus')
        with pytest.raises(ValueError, match='bogus'):
            SchemeSelectableBackend()

    def test_valid_scheme_injection(self):
        backend = SchemeSelectableBackend()
        alt = backend.with_properties(scheme='KeePassXC')
        assert alt._query('contoso', 'alice') == {
            'UserName': 'alice',
            'Title': 'contoso',
        }
        # the original backend is unaffected
        assert backend.scheme == 'default'
