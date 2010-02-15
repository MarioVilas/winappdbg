# Copyright (c) 2009-2010, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""
SQL client connector module for WinAppDbg.

@group Miscellaneous:
    SQLClient
"""

__revision__ = "$Id$"

__all__ = [ 'SQLClient' ]

class SQLClient(object):
    """
    SQL client connector for WinAppDbg.

    Open local databases with the L{open} method.
    Connect to remote databases with the L{connect} method.

    Currently supported local databases are:
     - SQLite (C{'sqlite://'}) using the C{sqlite3} or C{pysqlite2} module

    Currently supported remote databases are:
     - Microsoft SQL (C{"mssql://"}) using the C{pymssql} module
     - MySQL (C{"mysql://"}) using the C{MySQLdb} module
     - Oracle (C{"oracle://"}) using the C{cxOracle} module
     - PostgreSQL (C{"pgsql://"}) using the C{psycopg2}, C{pyPgSQL} or C{pgdb} module
    """

    @classmethod
    def __new__(cls, location):
        """
        Connect to a local or remote database.

        @note: Local filenames are assumed to be SQLite databases.

        @type  location: str
        @param location: Database location.
            It can be an URL or a local filename.

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        # Local filenames default to SQLite.
        if not is_url(location):
            return cls.open('sqlite', location)
        target = cls.parse_db_url(location)
        if target.host is None:
            dbtype = cls.get_db_type(location)
            return cls.open(dbtype, target.path)
##        return cls.connect(location)
        return cls._connect(target)

    @staticmethod
    def is_url(location):
        """
        @type  location: str
        @param location: Database location.

        @rtype:  bool
        @return: C{True} if the database location is an URL, or C{False} if
            it's a local filename.
        """
        # crude URL detection
        return location is None or not re.match('[^:]+://*', location)

    @classmethod
    def get_db_type(cls, url):
        """
        @type  url: str
        @param url: Database connection URL.

        @rtype:  str
        @return: Database type.
        """
        return urlparse.urlparse(url).scheme

    @staticmethod
    def parse_db_url(url):
        """
        Parse the database connection URL.

        @type  url: str
        @param url: Database connection URL.

        @rtype:  urlparse.ParseResult
        @return: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}
        """
        # Force urlparse to treat our custom schemes like http,
        # but sqlite: should be parsed like file://
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
        if scheme == 'sqlite':
            fake_scheme = 'file'
        else:
            fake_scheme = 'http'
        fake_url = urlparse.urlunparse( (fake_scheme, netloc, path, params, query, fragment) )
        _, netloc, path, params, query, fragment = urlparse.urlparse(fake_url)
        target = urlparse.ParseResult(scheme, netloc, path, params, query, fragment)
        return target

    @classmethod
    def open(cls, dbtype, filename):
        """
        Open a local database file.

        @type  dbtype: str
        @param dbtype: Database type.

        @type  filename: str
        @param filename: Local database file.

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        opener = getattr(cls, '_open_%s' % dbtype, None)
        if opener is None:
            raise ValueError, "Invalid database type: %s" % dbtype
        return opener(filename)

    @classmethod
    def _open_sqlite(cls, filename = None):
        """
        Open a local SQLite database file.

        @warning: This is a private method. Use L{open} instead.

        @type  filename: str
        @param filename: (Optional) Local database file.
            If C{None} or C{":memory:"} a memory database will be created.

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        try:
            import sqlite3 as dbapi2
        except ImportError:
            from pysqlite2 import dbapi2
        if filename is None:
            filename = ':memory:'
        return dbapi2.connect(filename)

    @classmethod
    def connect(cls, url):
        """
        Connect to the database using the given URL.

        @type  url: str
        @param url: Database connection URL.

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        target = cls.parse_db_url(url)
        return cls._connect(target)

    @classmethod
    def _connect(cls, target):
        """
        Connect to the database using the given URL.

        @warning: This is a private method. Use L{connect} instead.

        @type  target: urlparse.ParseResult
        @param target: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        protocol = target.scheme
        if '.' in protocol:
            raise ValueError, "Invalid database protocol: %s" % protocol
        connector = getattr(cls, '_connect_%s' % protocol, None)
        if connector is None:
            if protocol:
                msg = "Unknown database protocol: %s" % protocol
            else:
                msg = "Bad connection URL: %s" % url
            raise NotImplementedError, msg
        try:
            return connector(target)
        except ImportError:
            msg = "Missing database adapter for protocol: %s" % protocol
            raise NotImplementedError, msg

    @classmethod
    def _connect_osql(cls, target):
        """
        Connect to an Oracle database using the given parsed URL.

        @warning: This is a private method. Use L{connect} instead.

        @type  target: urlparse.ParseResult
        @param target: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        return cls._connect_oracle(target)

    @classmethod
    def _connect_oracle(cls, target):
        """
        Connect to an Oracle database using the given parsed URL.

        @warning: This is a private method. Use L{connect} instead.

        @type  target: urlparse.ParseResult
        @param target: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        import cxOracle
        port = target.port
        if port:
            port = int(port)
        else:
            port = 1521
        dsn = cxOracle.makedsn(target.hostname, port, target.path)
        connection = cxOracle.connect(target.username, target.password, dsn)
        return connection

    @classmethod
    def _connect_mysql(cls, target):
        """
        Connect to a MySQL database using the given parsed URL.

        @warning: This is a private method. Use L{connect} instead.

        @type  target: urlparse.ParseResult
        @param target: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        import MySQLdb
        return MySQLdb.connect( host    = target.netloc,
                                user    = target.username,
                                passwd  = target.password,
                                db      = target.path )

    @classmethod
    def _connect_mssql(cls, target):
        """
        Connect to a Microsoft SQL database using the given parsed URL.

        @warning: This is a private method. Use L{connect} instead.

        @type  target: urlparse.ParseResult
        @param target: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        import pymssql
        return pymssql.connect( host     = target.netloc,
                                user     = target.username,
                                password = target.password,
                                database = target.path )

    @classmethod
    def _connect_pq(cls, target):
        """
        Connect to a PostgreSQL database using the given parsed URL.

        @warning: This is a private method. Use L{connect} instead.

        @type  target: urlparse.ParseResult
        @param target: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        return cls._connect_pgsql(target)

    @classmethod
    def _connect_pgsql(cls, target):
        """
        Connect to a PostgreSQL database using the given parsed URL.

        @warning: This is a private method. Use L{connect} instead.

        @type  target: urlparse.ParseResult
        @param target: Parsed URL. Equivalent to the following tuple:
            I{(scheme, netloc, path, params, query, fragment)}

        @return: Connection object supporting the DBAPI-2.0 interface.
        """
        # XXX TODO: For python 3: import postgresql as dbapi2
        try:
            import psycopg2 as dbapi2
        except ImportError:
            try:
                import psycopg as dbapi2
            except ImportError:
                try:
                    import pyPgSQL as dbapi2
                except ImportError:
                    import pgdb as dbapi2
        return dbapi2.connect(  host     = target.netloc,
                                user     = target.username,
                                password = target.password,
                                database = target.path )

