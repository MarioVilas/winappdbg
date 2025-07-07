#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2025, Mario Vilas
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
Database storage support for crash dumps.

Supports both SQL databases (via SQLAlchemy) and MongoDB (via PyMongo).
The CrashDAO class automatically detects the database type based on the URL.
"""

__all__ = ['CrashDAO', 'CrashDAO_SQL', 'CrashDAO_Mongo']

import datetime
import warnings
from functools import wraps
from urllib.parse import urlparse
import json

# SQLAlchemy imports
try:
    from sqlalchemy import create_engine, Column, ForeignKey, Sequence, inspect
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, deferred
    from sqlalchemy.orm.exc import NoResultFound
    from sqlalchemy.types import Integer, BigInteger, Boolean, DateTime, String, \
                                LargeBinary, Enum
    from sqlalchemy.sql.expression import asc, desc
    SQL_AVAILABLE = True
except ImportError:
    SQL_AVAILABLE = False

# MongoDB imports
try:
    from pymongo import MongoClient
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False

from .crash import Crash, crash_decode, crash_encode
from .textio import CrashDump
from . import win32

#------------------------------------------------------------------------------

def Transactional(fn):
    """
    Decorator that wraps DAO methods to handle transactions automatically.

    It may only work with subclasses of :class:`BaseDAO`.
    """
    @wraps(fn)
    def wrapper(self, *argv, **argd):
        with self._session.begin():
            return fn(self, *argv, **argd)
    return wrapper

#------------------------------------------------------------------------------

class BaseDTO:
    """
    Customized declarative base for SQLAlchemy.
    """

    __table_args__ = {

        # Don't use MyISAM in MySQL. It doesn't support ON DELETE CASCADE.
        'mysql_engine': 'InnoDB',

        # Collate to UTF-8.
        'mysql_charset': 'utf8',

        }

BaseDTO = declarative_base(cls = BaseDTO)

#------------------------------------------------------------------------------

# TODO: if using mssql, check it's at least SQL Server 2005
#       (LIMIT and OFFSET support is required).
# TODO: if using mysql, check it's at least MySQL 5.0.3
#       (nested transactions are required).
# TODO: maybe in mysql check the tables are not myisam?
# TODO: maybe create the database if it doesn't exist?
# TODO: maybe add a method to compact the database?
#       http://stackoverflow.com/questions/1875885
#       http://www.sqlite.org/lang_vacuum.html
#       http://dev.mysql.com/doc/refman/5.1/en/optimize-table.html
#       http://msdn.microsoft.com/en-us/library/ms174459(v=sql.90).aspx

class BaseDAO:
    """
    Data Access Object base class.

    :type _url: sqlalchemy.url.URL
    :ivar _url: Database connection URL.

    :type _dialect: str
    :ivar _dialect: SQL dialect currently being used.

    :type _driver: str
    :ivar _driver: Name of the database driver currently being used.
        To get the actual Python module use ``_url.get_driver()`` instead.

    :type _session: sqlalchemy.orm.Session
    :ivar _session: Database session object.

    :type _new_session: class
    :cvar _new_session: Custom configured Session class used to create the
        :attr:`_session` instance variable.

    :type _echo: bool
    :cvar _echo: Set to ``True`` to print all SQL queries to standard output.
    """

    _echo = False

    _new_session = sessionmaker(autoflush = True,
                                expire_on_commit = True)

    def __init__(self, url, creator = None):
        """
        Connect to the database using the given connection URL.

        The current implementation uses SQLAlchemy and so it will support
        whatever database said module supports.

        :param str url:
            URL that specifies the database to connect to.

            Some examples:
             - Opening an SQLite file:
               ``dao = CrashDAO("sqlite:///C:\\some\\path\\database.sqlite")``
             - Connecting to a locally installed SQL Express database:
               ``dao = CrashDAO("mssql://.\\SQLEXPRESS/Crashes?trusted_connection=yes")``
             - Connecting to a MySQL database running locally, using the
               ``oursql`` library, authenticating as the "winappdbg" user with
               no password:
               ``dao = CrashDAO("mysql+oursql://winappdbg@localhost/Crashes")``
             - Connecting to a Postgres database running locally,
               authenticating with user and password:
               ``dao = CrashDAO("postgresql://winappdbg:winappdbg@localhost/Crashes")``

            For more information see the `SQLAlchemy documentation online <http://docs.sqlalchemy.org/en/latest/core/engines.html>`__.

            Note that in all dialects except for SQLite the database
            must already exist. The tables schema, however, is created
            automatically when connecting for the first time.

            To create the database in MSSQL, you can use the
            `SQLCMD <http://msdn.microsoft.com/en-us/library/ms180944.aspx>`__
            command::

                sqlcmd -Q "CREATE DATABASE Crashes"

            In MySQL you can use something like the following::

                mysql -u root -e "CREATE DATABASE Crashes;"

            And in Postgres::

                createdb Crashes -h localhost -U winappdbg -p winappdbg -O winappdbg

            Some small changes to the schema may be tolerated (for example,
            increasing the maximum length of string columns, or adding new
            columns with default values). Of course, it's best to test it
            first before making changes in a live database. This all depends
            very much on the SQLAlchemy version you're using, but it's best
            to use the latest version always.

        :param callable creator:
            (Optional) Callback function that creates the SQL
            database connection.

            Normally it's not necessary to use this argument. However in some
            odd cases you may need to customize the database connection.
        """

        # Parse the connection URL.
        parsed_url = make_url(url)
        schema = parsed_url.drivername
        if '+' in schema:
            dialect, driver = schema.split('+')
        else:
            dialect, driver = schema, 'base'
        dialect = dialect.strip().lower()
        driver = driver.strip()

        # Prepare the database engine arguments.
        arguments = {'echo' : self._echo}   # for debugging this module
        if creator is not None:
            arguments['creator'] = creator

        # Load the database engine.
        engine = create_engine(url, future=True, **arguments)

        # Create a new session.
        session = self._new_session(bind = engine)

        # Create the required tables if they don't exist.
        BaseDTO.metadata.create_all(engine)
        # TODO: create a dialect specific index on the "signature" column.

        # Set the instance properties.
        self._url     = parsed_url
        self._driver  = driver
        self._dialect = dialect
        self._session = session

#------------------------------------------------------------------------------

# Generates all possible memory access flags.
def _gen_valid_access_flags():
    f = []
    for a1 in ("---", "R--", "RW-", "RC-", "--X", "R-X", "RWX", "RCX", "???"):
        for a2 in ("G", "-"):
            for a3 in ("N", "-"):
                for a4 in ("W", "-"):
                    f.append("%s %s%s%s" % (a1, a2, a3, a4))
    return tuple(f)
_valid_access_flags = _gen_valid_access_flags()

# Enumerated types for the memory table.
n_MEM_ACCESS_ENUM = {"name" : "MEM_ACCESS_ENUM"}
n_MEM_ALLOC_ACCESS_ENUM = {"name" : "MEM_ALLOC_ACCESS_ENUM"}
MEM_ACCESS_ENUM = Enum(*_valid_access_flags,
                       **n_MEM_ACCESS_ENUM)
MEM_ALLOC_ACCESS_ENUM = Enum(*_valid_access_flags,
                             **n_MEM_ALLOC_ACCESS_ENUM)
MEM_STATE_ENUM  = Enum("Reserved", "Commited", "Free", "Unknown",
                       name = "MEM_STATE_ENUM")
MEM_TYPE_ENUM   = Enum("Image", "Mapped", "Private", "Unknown",
                       name = "MEM_TYPE_ENUM")

# Cleanup the namespace.
del _gen_valid_access_flags
del _valid_access_flags
del n_MEM_ACCESS_ENUM
del n_MEM_ALLOC_ACCESS_ENUM

#------------------------------------------------------------------------------

class MemoryDTO (BaseDTO):
    """
    Database mapping for memory dumps.
    """

    # Declare the table mapping.
    __tablename__ = 'memory'
    id            = Column(Integer, Sequence(__tablename__ + '_seq'),
                           primary_key = True, autoincrement = True)
    crash_id      = Column(Integer, ForeignKey('crashes.id',
                                               ondelete = 'CASCADE',
                                               onupdate = 'CASCADE'),
                           nullable = False)
    address       = Column(BigInteger, nullable = False, index = True)
    size          = Column(BigInteger, nullable = False)
    state         = Column(MEM_STATE_ENUM, nullable = False)
    access        = Column(MEM_ACCESS_ENUM)
    type          = Column(MEM_TYPE_ENUM)
    alloc_base    = Column(BigInteger)
    alloc_access  = Column(MEM_ALLOC_ACCESS_ENUM)
    filename      = Column(String)
    content       = deferred(Column(LargeBinary))

    def __init__(self, crash_id, mbi):
        """
        Process a :class:`win32.MemoryBasicInformation` object for database storage.
        """

        # Crash ID.
        self.crash_id = crash_id

        # Address.
        self.address = mbi.BaseAddress

        # Size.
        self.size = mbi.RegionSize

        # State (free or allocated).
        if   mbi.State == win32.MEM_RESERVE:
            self.state = "Reserved"
        elif mbi.State == win32.MEM_COMMIT:
            self.state = "Commited"
        elif mbi.State == win32.MEM_FREE:
            self.state = "Free"
        else:
            self.state = "Unknown"

        # Page protection bits (R/W/X/G).
        if mbi.State != win32.MEM_COMMIT:
            self.access = None
        else:
            self.access = self._to_access(mbi.Protect)

        # Type (file mapping, executable image, or private memory).
        if   mbi.Type == win32.MEM_IMAGE:
            self.type = "Image"
        elif mbi.Type == win32.MEM_MAPPED:
            self.type = "Mapped"
        elif mbi.Type == win32.MEM_PRIVATE:
            self.type = "Private"
        elif mbi.Type == 0:
            self.type = None
        else:
            self.type = "Unknown"

        # Allocation info.
        self.alloc_base   = mbi.AllocationBase
        if not mbi.AllocationProtect:
            self.alloc_access = None
        else:
            self.alloc_access = self._to_access(mbi.AllocationProtect)

        # Filename (for memory mappings).
        try:
            self.filename = mbi.filename
        except AttributeError:
            self.filename = None

        # Memory contents.
        try:
            self.content = mbi.content
        except AttributeError:
            self.content = None

    def _to_access(self, protect):
        if   protect & win32.PAGE_NOACCESS:
            access = "--- "
        elif protect & win32.PAGE_READONLY:
            access = "R-- "
        elif protect & win32.PAGE_READWRITE:
            access = "RW- "
        elif protect & win32.PAGE_WRITECOPY:
            access = "RC- "
        elif protect & win32.PAGE_EXECUTE:
            access = "--X "
        elif protect & win32.PAGE_EXECUTE_READ:
            access = "R-X "
        elif protect & win32.PAGE_EXECUTE_READWRITE:
            access = "RWX "
        elif protect & win32.PAGE_EXECUTE_WRITECOPY:
            access = "RCX "
        else:
            access = "??? "
        if   protect & win32.PAGE_GUARD:
            access += "G"
        else:
            access += "-"
        if   protect & win32.PAGE_NOCACHE:
            access += "N"
        else:
            access += "-"
        if   protect & win32.PAGE_WRITECOMBINE:
            access += "W"
        else:
            access += "-"
        return access

    def toMBI(self, getMemoryDump = False):
        """
        Returns a :class:`win32.MemoryBasicInformation` object using the data
        retrieved from the database.

        :param bool getMemoryDump:
            (Optional) If ``True`` retrieve the memory dump.
            Defaults to ``False`` since this may be a costly operation.

        :rtype:  win32.MemoryBasicInformation
        :return: Memory block information.
        """
        mbi = win32.MemoryBasicInformation()
        mbi.BaseAddress = self.address
        mbi.RegionSize  = self.size
        mbi.State       = self._parse_state(self.state)
        mbi.Protect     = self._parse_access(self.access)
        mbi.Type        = self._parse_type(self.type)
        if self.alloc_base is not None:
            mbi.AllocationBase = self.alloc_base
        else:
            mbi.AllocationBase = mbi.BaseAddress
        if self.alloc_access is not None:
            mbi.AllocationProtect = self._parse_access(self.alloc_access)
        else:
            mbi.AllocationProtect = mbi.Protect
        if self.filename is not None:
            mbi.filename = self.filename
        if getMemoryDump and self.content is not None:
            mbi.content  = self.content
        return mbi

    @staticmethod
    def _parse_state(state):
        if state:
            if state == "Reserved":
                return win32.MEM_RESERVE
            if state == "Commited":
                return win32.MEM_COMMIT
            if state == "Free":
                return win32.MEM_FREE
        return 0

    @staticmethod
    def _parse_type(type):
        if type:
            if type == "Image":
                return win32.MEM_IMAGE
            if type == "Mapped":
                return win32.MEM_MAPPED
            if type == "Private":
                return win32.MEM_PRIVATE
            return -1
        return 0

    @staticmethod
    def _parse_access(access):
        if not access:
            return 0
        perm = access[:3]
        if   perm == "R--":
            protect = win32.PAGE_READONLY
        elif perm == "RW-":
            protect = win32.PAGE_READWRITE
        elif perm == "RC-":
            protect = win32.PAGE_WRITECOPY
        elif perm == "--X":
            protect = win32.PAGE_EXECUTE
        elif perm == "R-X":
            protect = win32.PAGE_EXECUTE_READ
        elif perm == "RWX":
            protect = win32.PAGE_EXECUTE_READWRITE
        elif perm == "RCX":
            protect = win32.PAGE_EXECUTE_WRITECOPY
        else:
            protect = win32.PAGE_NOACCESS
        if access[5] == "G":
            protect = protect | win32.PAGE_GUARD
        if access[6] == "N":
            protect = protect | win32.PAGE_NOCACHE
        if access[7] == "W":
            protect = protect | win32.PAGE_WRITECOMBINE
        return protect

#------------------------------------------------------------------------------

class CrashDTO (BaseDTO):
    """
    Database mapping for crash dumps.
    """

    # Table name.
    __tablename__ = "crashes"

    # Primary key.
    id = Column(Integer, Sequence(__tablename__ + '_seq'),
                primary_key = True, autoincrement = True)

    # Timestamp.
    timestamp = Column(DateTime, nullable = False, index = True)

    # Exploitability test.
    exploitable = Column(Integer, nullable = False)
    exploitability_rule = Column(String(32), nullable = False)
    exploitability_rating = Column(String(32), nullable = False)
    exploitability_desc = Column(String, nullable = False)

    # Platform description.
    os = Column(String(32), nullable = False)
    arch = Column(String(16), nullable = False)
    bits = Column(Integer, nullable = False)    # Integer(4) is deprecated :(

    # Event description.
    event = Column(String, nullable = False)
    pid = Column(Integer, nullable = False)
    tid = Column(Integer, nullable = False)
    pc = Column(BigInteger, nullable = False)
    sp = Column(BigInteger, nullable = False)
    fp = Column(BigInteger, nullable = False)
    pc_label = Column(String, nullable = False)

    # Exception description.
    exception = Column(String(64))
    exception_text = Column(String(64))
    exception_address = Column(BigInteger)
    exception_label = Column(String)
    first_chance = Column(Boolean)
    fault_type = Column(Integer)
    fault_address = Column(BigInteger)
    fault_label = Column(String)
    fault_disasm = Column(String)
    stack_trace = Column(String)

    # Environment description.
    command_line = Column(String)
    environment = Column(String)

    # Debug strings.
    debug_string = Column(String)

    # Notes.
    notes = Column(String)

    # Heuristic signature.
    signature = Column(String, nullable = False)

    # Pickled Crash object, minus the memory dump.
    data = deferred(Column(LargeBinary, nullable = False))

    def __init__(self, crash):
        """
        :param Crash crash: :class:`Crash` object to store into the database.
        """

        # Timestamp and signature.
        self.timestamp = datetime.datetime.fromtimestamp( crash.timeStamp )
        self.signature = crash.signature

        # Marshalled Crash object, minus the memory dump.
        # This code is *not* thread safe!
        memoryMap = crash.memoryMap
        try:
            crash.memoryMap = None
            self.data = json.dumps(crash, default=crash_encode).encode('utf-8')
        finally:
            crash.memoryMap = memoryMap

        # Exploitability test.
        self.exploitability_rating, \
        self.exploitability_rule,   \
        self.exploitability_desc  = crash.isExploitable()

        # Exploitability test as an integer result (for sorting).
        self.exploitable = [
                                "Not an exception",
                                "Not exploitable",
                                "Not likely exploitable",
                                "Unknown",
                                "Probably exploitable",
                                "Exploitable",
                            ].index(self.exploitability_rating)

        # Platform description.
        self.os   = crash.os
        self.arch = crash.arch
        self.bits = crash.bits

        # Event description.
        self.event    = crash.eventName
        self.pid      = crash.pid
        self.tid      = crash.tid
        self.pc       = crash.pc
        self.sp       = crash.sp
        self.fp       = crash.fp
        self.pc_label = crash.labelPC

        # Exception description.
        self.exception         = crash.exceptionName
        self.exception_text    = crash.exceptionDescription
        self.exception_address = crash.exceptionAddress
        self.exception_label   = crash.exceptionLabel
        self.first_chance      = crash.firstChance
        self.fault_type        = crash.faultType
        self.fault_address     = crash.faultAddress
        self.fault_label       = crash.faultLabel
        self.fault_disasm      = CrashDump.dump_code( crash.faultDisasm,
                                                      crash.pc )
        self.stack_trace       = CrashDump.dump_stack_trace_with_labels(
                                                      crash.stackTracePretty )

        # Command line.
        self.command_line = crash.commandLine

        # Environment.
        if crash.environment:
            envList = sorted(crash.environment.items())
            environment = ''
            for envKey, envVal in envList:
                # Must concatenate here instead of using a substitution,
                # so strings can be automatically promoted to Unicode.
                environment += envKey + '=' + envVal + '\n'
            if environment:
                self.environment = environment

        # Debug string.
        self.debug_string = crash.debugString

        # Notes.
        self.notes = crash.notesReport()

    def toCrash(self, getMemoryDump = False):
        """
        Returns a :class:`Crash` object using the data retrieved from the database.

        :param bool getMemoryDump:
            If ``True`` retrieve the memory dump.
            Defaults to ``False`` since this may be a costly operation.

        :rtype:  Crash
        :return: Crash object.
        """
        crash = json.loads(self.data.decode('utf-8'), object_hook=crash_decode)
        if not isinstance(crash, Crash):
            raise TypeError(
                "Expected Crash instance, got %s instead" % type(crash))
        crash._rowid = self.id
        if not crash.memoryMap:
            memory = getattr(self, "memory", [])
            if memory:
                crash.memoryMap = [dto.toMBI(getMemoryDump) for dto in memory]
        return crash

#==============================================================================

# TODO: add a method to modify already stored crash dumps.

class CrashDAO_SQL (BaseDAO):
    """
    Data Access Object to read, write and search for :class:`Crash` objects
    in a SQL database using SQLAlchemy.
    """

    @Transactional
    def add(self, crash, allow_duplicates = True):
        """
        Add a new crash dump to the database, optionally filtering them by
        signature to avoid duplicates.

        :param Crash crash: Crash object.

        :param bool allow_duplicates:
            (Optional)
            ``True`` to always add the new crash dump.
            ``False`` to only add the crash dump if no other crash with the
            same signature is found in the database.

            Sometimes, your fuzzer turns out to be *too* good. Then you find
            youself browsing through gigabytes of crash dumps, only to find

            a handful of actual bugs in them. This simple heuristic filter
            saves you the trouble by discarding crashes that seem to be similar
            to another one you've already found.
        """
        if not SQL_AVAILABLE:
            raise ImportError("sqlalchemy is required for SQL database support. "
                            "Install it with: pip install sqlalchemy")

        # Filter out duplicated crashes, if requested.
        if not allow_duplicates:
            if self._session.query(CrashDTO.id)                \
                            .filter_by(signature = crash.signature) \
                            .count() > 0:
                return

        # Fill out a new row for the crashes table.
        crash_id = self.__add_crash(crash)

        # Fill out new rows for the memory dump.
        self.__add_memory(crash_id, crash.memoryMap)

        # On success set the row ID for the Crash object.
        # WARNING: In nested calls, make sure to delete
        # this property before a session rollback!
        crash._rowid = crash_id

    # Store the Crash object into the crashes table.
    def __add_crash(self, crash):
        session = self._session
        r_crash = None
        try:

            # Fill out a new row for the crashes table.
            r_crash = CrashDTO(crash)
            session.add(r_crash)

            # Flush and get the new row ID.
            session.flush()
            crash_id = r_crash.id

        finally:
            try:

                # Make the ORM forget the CrashDTO object.
                if r_crash is not None:
                    session.expire(r_crash)

            finally:

                # Delete the last reference to the CrashDTO
                # object, so the Python garbage collector claims it.
                del r_crash

        # Return the row ID.
        return crash_id

    # Store the memory dump into the memory table.
    def __add_memory(self, crash_id, memoryMap):
        session = self._session
        if memoryMap:
            for mbi in memoryMap:
                r_mem = MemoryDTO(crash_id, mbi)
                session.add(r_mem)
            session.flush()

    @Transactional
    def find(self,
             signature = None, order = 0,
             since     = None, until = None,
             offset    = None, limit = None):
        """
        Retrieve all crash dumps in the database, optionally filtering them by
        signature and timestamp, and/or sorting them by timestamp.

        Results can be paged to avoid consuming too much memory if the database
        is large.

        .. seealso:: :meth:`find_by_example`

        :param object signature:
            (Optional) Return only through crashes matching this signature.
            See :attr:`Crash.signature` for more details.

        :param int order:
            (Optional) Sort by timestamp.
            If ``== 0``, results are not sorted.
            If ``> 0``, results are sorted from older to newer.
            If ``< 0``, results are sorted from newer to older.

        :param datetime.datetime since:
            (Optional) Return only the crashes after and
            including this date and time.

        :param datetime.datetime until:
            (Optional) Return only the crashes before this date
            and time, not including it.

        :param int offset:
            (Optional) Skip the first *offset* results.

        :param int limit:
            (Optional) Return at most *limit* results.

        :rtype:  list[Crash]
        :return: List of :class:`Crash` objects.
        """

        # Validate the parameters.
        if since and until and since > until:
            warnings.warn("CrashDAO.find() got the 'since' and 'until'"
                          " arguments reversed, corrected automatically.")
            since, until = until, since
        if limit is not None and not limit:
            warnings.warn("CrashDAO.find() was set a limit of 0 results,"
                          " returning without executing a query.")
            return []

        # Build the SQL query.
        query = self._session.query(CrashDTO)
        if signature is not None:
            query = query.filter(CrashDTO.signature == signature)
        if since:
            query = query.filter(CrashDTO.timestamp >= since)
        if until:
            query = query.filter(CrashDTO.timestamp < until)
        if order:
            if order > 0:
                query = query.order_by(asc(CrashDTO.timestamp))
            else:
                query = query.order_by(desc(CrashDTO.timestamp))
        else:
            # Default ordering is by row ID, to get consistent results.
            # Also some database engines require ordering when using offsets.
            query = query.order_by(asc(CrashDTO.id))
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)

        # Execute the SQL query and convert the results.
        try:
            return [dto.toCrash() for dto in query.all()]
        except NoResultFound:
            return []

    @Transactional
    def find_by_example(self, crash, offset = None, limit = None):
        """
        Find all crash dumps that have common properties with the crash dump
        provided.

        Results can be paged to avoid consuming too much memory if the database
        is large.

        .. seealso:: :meth:`find`

        :param Crash crash:
            Crash object to compare with. Fields set to ``None`` are ignored,
            all other fields but the signature are used in the comparison.

            To search for signature instead use the :meth:`find` method.

        :param int offset:
            (Optional) Skip the first *offset* results.

        :param int limit:
            (Optional) Return at most *limit* results.

        :rtype:  list[Crash]
        :return: List of similar crash dumps found.
        """

        # Validate the parameters.
        if limit is not None and not limit:
            warnings.warn("CrashDAO.find_by_example() was set a limit of 0"
                          " results, returning without executing a query.")
            return []

        # Build the query.
        query = self._session.query(CrashDTO)

        # Order by row ID to get consistent results.
        # Also some database engines require ordering when using offsets.
        query = query.order_by(asc(CrashDTO.id))

        # Build a CrashDTO from the Crash object.
        dto = CrashDTO(crash)

        # Filter all the fields in the crashes table that are present in the
        # CrashDTO object and not set to None, except for the row ID.
        for attr in inspect(CrashDTO).attrs:
            if attr.key not in ('id', 'signature', 'data', 'timestamp'):
                value = getattr(dto, attr.key, None)
                if value is not None:
                    query = query.filter(attr == value)

        # Page the query.
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)

        # Execute the SQL query and convert the results.
        try:
            return [_dto.toCrash() for _dto in query.all()]
        except NoResultFound:
            return []

    @Transactional
    def count(self, signature = None):
        """
        Counts how many crash dumps have been stored in this database.
        Optionally filters the count by heuristic signature.

        :param object signature:
            (Optional) Count only the crashes that match this signature.
            See :attr:`Crash.signature` for more details.

        :rtype:  int
        :return: Count of crash dumps stored in this database.
        """
        query = self._session.query(CrashDTO.id)
        if signature:
            query = query.filter_by(signature = signature)
        return query.count()

    @Transactional
    def delete(self, crash):
        """
        Remove the given crash dump from the database.

        :param Crash crash: Crash dump to remove.
        """
        query = self._session.query(CrashDTO).filter_by(id = crash._rowid)
        query.delete(synchronize_session = False)
        del crash._rowid

#==============================================================================

class CrashDAO_Mongo:
    """
    Data Access Object to read, write and search for :class:`Crash` objects
    in a MongoDB database using PyMongo.
    """

    def __init__(self, url, creator=None):
        """
        :param str url: Database connection URL.
        :param callable creator: Optional callback to create custom database connections.
        """
        if not MONGODB_AVAILABLE:
            raise ImportError("pymongo is required for MongoDB support. "
                            "Install it with: pip install pymongo")

        parsed = urlparse(url)

        # Extract database name from path.
        if parsed.path and len(parsed.path) > 1:
            self.db_name = parsed.path[1:]  # Remove leading '/'
        else:
            self.db_name = "winappdbg"

        # Create connection URL preserving query parameters but removing database name from path.
        if parsed.username and parsed.password:
            if parsed.query:
                connection_url = f"mongodb://{parsed.username}:{parsed.password}@{parsed.netloc}/?{parsed.query}"
            else:
                connection_url = f"mongodb://{parsed.username}:{parsed.password}@{parsed.netloc}"
        else:
            if parsed.query:
                connection_url = f"mongodb://{parsed.netloc}/?{parsed.query}"
            else:
                connection_url = f"mongodb://{parsed.netloc}"

        self.client = MongoClient(connection_url)
        self.db = self.client[self.db_name]
        self.crashes = self.db.crashes
        self.memory = self.db.memory

        # Create indexes for performance.
        self._create_indexes()

    def _create_indexes(self):
        """Create database indexes for performance."""

        # Create indexes on commonly queried fields.
        self.crashes.create_index([("signature", 1)])
        self.crashes.create_index([("timestamp", -1)])
        self.crashes.create_index([("pid", 1)])
        self.crashes.create_index([("exploitable", -1)])
        self.crashes.create_index([("exception", 1)])
        self.crashes.create_index([("pc", 1)])

        # Index for memory lookups.
        self.memory.create_index([("crash_id", 1)])
        self.memory.create_index([("address", 1)])
        self.memory.create_index([("state", 1)])
        self.memory.create_index([("protect", 1)])

    def add(self, crash, allow_duplicates=True):
        """
        Add a new crash dump to the database.

        :param Crash crash: Crash object.
        :param bool allow_duplicates: If False, skip if signature already exists.
        """
        # Filter out duplicated crashes, if requested.
        if not allow_duplicates:
            if self.crashes.find_one({"signature": crash.signature}):
                return

        # Store the crash using the same approach as SQL version.
        crash_id = self._add_crash(crash)

        # Store memory map separately.
        self._add_memory(crash_id, crash.memoryMap)

        # Set the row ID for the Crash object.
        crash._rowid = crash_id

    def _add_crash(self, crash):
        """Store the Crash object using crash_encode for all serialization."""

        # Marshalled Crash object, minus the memory dump (same as SQL version).
        memoryMap = crash.memoryMap
        try:
            crash.memoryMap = None
            # Use crash_encode for the entire object.
            crash_json = json.dumps(crash, default=crash_encode)
        finally:
            crash.memoryMap = memoryMap

        # Extract exploitability for indexing.
        exploitable_result = crash.isExploitable()
        exploitable_index = [
            "Not an exception",
            "Not exploitable",
            "Not likely exploitable",
            "Unknown",
            "Probably exploitable",
            "Exploitable",
        ].index(exploitable_result[0])

        # Create document with serialized data and index fields.
        doc = {
            # Serialized crash data.
            "data": crash_json,

            # Index fields for searching (extracted from crash object).
            "timestamp": datetime.datetime.fromtimestamp(crash.timeStamp),
            "signature": crash.signature,
            "exploitable": exploitable_index,
            "exploitability_rating": exploitable_result[0],
            "exploitability_rule": exploitable_result[1],
            "exploitability_desc": exploitable_result[2],
            "os": crash.os,
            "arch": crash.arch,
            "bits": crash.bits,
            "event": crash.eventName,
            "pid": crash.pid,
            "tid": crash.tid,
            "pc": crash.pc,
            "sp": crash.sp,
            "fp": crash.fp,
            "exception": crash.exceptionName,
            "exception_address": crash.exceptionAddress,
            "first_chance": crash.firstChance,
            "fault_type": crash.faultType,
            "fault_address": crash.faultAddress,
        }

        # Insert and return the ID.
        result = self.crashes.insert_one(doc)
        return result.inserted_id

    def _add_memory(self, crash_id, memory_map):
        """Store memory map using crash_encode for serialization."""
        if not memory_map:
            return

        memory_docs = []
        for mbi in memory_map:
            # Use crash_encode to serialize the MBI object.
            mbi_data = crash_encode(mbi)

            # Create document with serialized data and index fields.
            doc = {
                "crash_id": crash_id,
                "data": json.dumps(mbi_data, default=crash_encode),
                # Index fields for searching
                "address": mbi.BaseAddress,
                "size": mbi.RegionSize,
                "state": mbi.State,
                "protect": mbi.Protect,
                "type": mbi.Type,
                "alloc_base": mbi.AllocationBase,
                "alloc_protect": mbi.AllocationProtect,
                "filename": getattr(mbi, 'filename', None),
            }
            memory_docs.append(doc)

        if memory_docs:
            self.memory.insert_many(memory_docs)

    def find(self, signature=None, order=0, since=None, until=None, offset=None, limit=None):
        """
        Find crash dumps in the database.

        :param str signature: Filter by signature.
        :param int order: Sort order (0=newest first, 1=oldest first).
        :param datetime since: Filter crashes after this date.
        :param datetime until: Filter crashes before this date.
        :param int offset: Skip this many results.
        :param int limit: Maximum number of results.

        :rtype: generator
        :return: Generator yielding Crash objects.
        """
        query = {}

        if signature:
            query["signature"] = signature

        if since or until:
            date_query = {}
            if since:
                date_query["$gte"] = since
            if until:
                date_query["$lte"] = until
            query["timestamp"] = date_query

        sort_order = 1 if order == 1 else -1
        cursor = self.crashes.find(query).sort("timestamp", sort_order)

        if offset:
            cursor = cursor.skip(offset)
        if limit:
            cursor = cursor.limit(limit)

        for doc in cursor:
            yield self._doc_to_crash(doc, get_memory_dump=False)

    def _doc_to_crash(self, doc, get_memory_dump=False):
        """Convert MongoDB document back to Crash object using crash_decode."""

        # Use the stored JSON data with crash_decode (same as SQL version).
        crash = json.loads(doc["data"], object_hook=crash_decode)

        if not isinstance(crash, Crash):
            raise TypeError(f"Expected Crash instance, got {type(crash)} instead")

        crash._rowid = doc["_id"]

        # Load memory map if requested and not already present.
        if get_memory_dump and not crash.memoryMap:
            memory_docs = list(self.memory.find({"crash_id": doc["_id"]}))
            if memory_docs:
                crash.memoryMap = [self._doc_to_mbi(mem_doc) for mem_doc in memory_docs]

        return crash

    def _doc_to_mbi(self, doc):
        """Convert memory document back to MemoryBasicInformation using crash_decode."""
        mbi_data = json.loads(doc["data"])
        mbi = crash_decode(mbi_data)
        return mbi

    def find_by_example(self, crash, offset=None, limit=None):
        """
        Find crashes similar to the given example.
        """
        query = {"signature": crash.signature}

        cursor = self.crashes.find(query).sort("timestamp", -1)

        if offset:
            cursor = cursor.skip(offset)
        if limit:
            cursor = cursor.limit(limit)

        for doc in cursor:
            yield self._doc_to_crash(doc)

    def count(self, signature=None):
        """
        Count crashes in the database.
        """
        query = {}
        if signature:
            query["signature"] = signature
        return self.crashes.count_documents(query)

    def delete(self, crash):
        """
        Delete a crash from the database.
        """
        if hasattr(crash, '_rowid'):

            # Delete memory records first.
            self.memory.delete_many({"crash_id": crash._rowid})

            # Delete crash record.
            result = self.crashes.delete_one({"_id": crash._rowid})

            return result.deleted_count > 0

        return False

#==============================================================================

class CrashDAO:
    """
    Factory class that creates the appropriate DAO implementation based on the URL.

    Supports both SQL databases (via SQLAlchemy) and MongoDB.
    """

    def __new__(cls, url, creator=None):
        """
        Create the appropriate DAO implementation based on the URL scheme.

        :param str url: Database connection URL
        :param callable creator: Optional creator function (SQL only)
        :rtype: CrashDAO_SQL or CrashDAO_Mongo
        :return: DAO instance
        """
        if url.startswith('mongodb://') or url.startswith('mongodb+srv://'):
            return CrashDAO_Mongo(url, creator)
        else:
            return CrashDAO_SQL(url, creator)
