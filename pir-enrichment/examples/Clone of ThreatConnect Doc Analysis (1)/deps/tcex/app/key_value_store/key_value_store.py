"""TcEx Framework Module"""

# standard library
import logging

# third-party
from redis import Redis

from ...input.field_type.sensitive import Sensitive
from ...pleb.cached_property import cached_property
from ...pleb.scoped_property import scoped_property
from ...requests_tc.tc_session import TcSession
from .key_value_api import KeyValueApi
from .key_value_mock import KeyValueMock
from .key_value_redis import KeyValueRedis
from .redis_client import RedisClient
from .redis_client_ssl import RedisClientSsl

# get logger
_logger = logging.getLogger(__name__.split('.', maxsplit=1)[0])


class KeyValueStore:
    """TcEx Module"""

    def __init__(
        self,
        session_tc: TcSession,
        tc_kvstore_host: str,
        tc_kvstore_port: int,
        tc_kvstore_type: str,
        tc_playbook_kvstore_id: int = 0,
        tc_kvstore_pass: Sensitive | None = None,
        tc_kvstore_user: str | None = None,
        tc_kvstore_tls_enabled: bool = False,
        tc_kvstore_tls_port: int = 6379,
        tc_svc_broker_cacert_file: str | None = None,
        tc_svc_broker_cert_file: str | None = None,
        tc_svc_broker_key_file: str | None = None,
    ):
        """Initialize the class properties."""
        self.session_tc = session_tc
        self.tc_kvstore_host = tc_kvstore_host
        self.tc_kvstore_pass = tc_kvstore_pass
        self.tc_kvstore_port = tc_kvstore_port
        self.tc_kvstore_type = tc_kvstore_type
        self.tc_kvstore_user = tc_kvstore_user
        self.tc_kvstore_tls_enabled = tc_kvstore_tls_enabled
        self.tc_kvstore_tls_port = tc_kvstore_tls_port
        self.tc_playbook_kvstore_id = tc_playbook_kvstore_id
        self.tc_svc_broker_cacert_file = tc_svc_broker_cacert_file
        self.tc_svc_broker_cert_file = tc_svc_broker_cert_file
        self.tc_svc_broker_key_file = tc_svc_broker_key_file

        # properties
        self.log = _logger

    @scoped_property
    def client(self) -> KeyValueApi | KeyValueMock | KeyValueRedis:
        """Return the correct KV store for this execution.

        The TCKeyValueAPI KV store is limited to two operations (create and read),
        while the Redis kvstore wraps a few other Redis methods.
        """
        if self.tc_kvstore_type == 'Redis':
            # submodule doesn't have scoped_property decorator, so resolution of type doesn't work
            return KeyValueRedis(self.redis_client)  # type: ignore

        if self.tc_kvstore_type == 'TCKeyValueAPI':
            return KeyValueApi(self.session_tc)

        if self.tc_kvstore_type == 'Mock':
            self.log.warning(
                'Using mock key-value store. This should *never* happen when running in-platform.'
            )
            return KeyValueMock()

        ex_msg = f'Invalid KV Store Type: ({self.tc_kvstore_type})'
        raise RuntimeError(ex_msg)

    @cached_property
    def client_kvr(self) -> KeyValueRedis:
        """Return the Redis KV store client.

        This property should only be used when the KV store type is Redis.
        """
        return KeyValueRedis(self.redis_client)

    @staticmethod
    def get_redis_client(host: str, port: int, db: int = 0, **kwargs) -> Redis:
        """Return a *new* instance of Redis client.

        For a full list of kwargs see https://redis-py.readthedocs.io/en/latest/#redis.Connection.

        Args:
            host: The REDIS host. Defaults to localhost.
            port: The REDIS port. Defaults to 6379.
            db: The REDIS db. Defaults to 0.
            **kwargs: Additional keyword arguments.

        Keyword Args:
            errors (str): The REDIS errors policy (e.g. strict).
            max_connections (int): The maximum number of connections to REDIS.
            password (Sensitive): The REDIS password.
            socket_timeout (int): The REDIS socket timeout.
            timeout (int): The REDIS Blocking Connection Pool timeout value.
            username (str): The REDIS username.
        """
        return RedisClient(host=host, port=port, db=db, **kwargs).client

    @staticmethod
    def get_redis_client_ssl(
        host: str,
        port: int,
        db: int = 0,
        username: str | None = None,
        password: Sensitive | str | None = None,
        ssl_ca_certs: str | None = None,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
        **kwargs,
    ) -> Redis:
        """Return a *new* instance of Redis client.

        For a full list of kwargs see https://redis-py.readthedocs.io/en/latest/#redis.Connection.
        """
        password = password.value if isinstance(password, Sensitive) else password
        return RedisClientSsl(
            host=host,
            port=port,
            db=db,
            username=username,
            password=password,
            ssl_ca_certs=ssl_ca_certs,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            **kwargs,
        ).client

    @scoped_property
    def redis_client(self) -> Redis:
        """Return redis client instance configure for Playbook/Service Apps."""
        if self.tc_kvstore_tls_enabled is True:
            return self.get_redis_client_ssl(
                host=self.tc_kvstore_host,
                port=self.tc_kvstore_tls_port,
                db=self.tc_playbook_kvstore_id,
                username=self.tc_kvstore_user,
                password=self.tc_kvstore_pass,
                ssl_ca_certs=self.tc_svc_broker_cacert_file,
                ssl_certfile=self.tc_svc_broker_cert_file,
                ssl_keyfile=self.tc_svc_broker_key_file,
            )
        return self.get_redis_client(
            host=self.tc_kvstore_host,
            port=self.tc_kvstore_port,
            db=0,
        )
