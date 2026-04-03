"""TcEx Framework Module"""

# standard library
import atexit
from functools import cached_property

# third-party
import redis


class RedisClientSsl:
    """A shared REDIS client connection using a Connection Pool.

    Initialize a single shared redis.connection.ConnectionPool.
    For a full list of kwargs see https://redis-py.readthedocs.io/en/latest/#redis.Connection.

    Args:
        host: The Redis host. Defaults to localhost.
        port: The Redis port. Defaults to 6379.
        db: The Redis db. Defaults to 0.
        username (str, kwargs): The REDIS username.
        password (str, kwargs): The REDIS password.
        ssl_certfile (str, kwargs): The REDIS SSL certfile.
        ssl_keyfile (str, kwargs): The REDIS SSL keyfile.
        errors (str, kwargs): The REDIS errors policy (e.g. strict).
        max_connections (int, kwargs): The maximum number of connections to REDIS.
        socket_timeout (int, kwargs): The REDIS socket timeout.
        timeout (int, kwargs): The REDIS Blocking Connection Pool timeout value.
    """

    def __init__(
        self,
        host: str = 'localhost',
        port: int = 6379,
        db: int = 0,
        username: str | None = None,
        password: str | None = None,
        ssl_ca_certs: str | None = None,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
        **kwargs,
    ):
        """Initialize class properties

        Redis Client wrapper will support 4 modes:
        1. Redis Connection Pool non-secured
        2. Redis Connection Pool secured
        3. Redis Blocking Connection Pool non-secured
        4. Redis Blocking Connection Pool secured
        """
        self.pool = redis.ConnectionPool(
            connection_class=redis.SSLConnection,
            db=db,
            host=host,
            password=password,
            port=port,
            username=username,
            ssl_cert_reqs='required',
            ssl_ca_certs=ssl_ca_certs,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            **kwargs,
        )
        atexit.register(self.pool.disconnect)

    @cached_property
    def client(self) -> redis.Redis:
        """Return an instance of redis.client.Redis."""
        client = redis.Redis(connection_pool=self.pool)
        atexit.register(client.close)
        return client
