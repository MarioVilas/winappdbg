#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2012, Mario Vilas
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
SQL database storage support.

@group Crash reporting:
    CrashDAO
"""

__revision__ = "$Id$"

__all__ = ['CrashDAO']

import sqlite3
import datetime
import warnings

from sqlalchemy import create_engine, Column, ForeignKey, Sequence
from sqlalchemy.engine.url import URL
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.interfaces import PoolListener
from sqlalchemy.orm import sessionmaker, relationship, backref, deferred
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from sqlalchemy.schema import Index
from sqlalchemy.types import Integer, BigInteger, Boolean, DateTime, \
                             LargeBinary, Enum, PickleType, TEXT, VARCHAR

from crash import Crash, Marshaller, pickle, HIGHEST_PROTOCOL
from textio import CrashDump
import win32

try:
    from decorator import decorator
except ImportError:
    import functools
    def decorator(w):
        """
        The C{decorator} module was not found. You can install it from:
        U{http://pypi.python.org/pypi/decorator/}
        """
        def d(fn):
            @functools.wraps(fn)
            def x(*argv, **argd):
                return w(fn, *argv, **argd)
            return x
        return d

#==============================================================================

class BaseDTO (object):
    """
    Customized declarative base for SQLAlchemy.
    """

    __table_args__ = {

        # Don't use MyISAM in MySQL. It doesn't support ON DELETE CASCADE.
        'mysql_engine': 'InnoDB',

        # Don't use BlitzDB in Drizzle. It doesn't support foreign keys.
        'drizzle_engine': 'InnoDB',

        # Collate to UTF-8.
        'mysql_charset': 'utf8',

        }

BaseDTO = declarative_base(cls = BaseDTO)

#==============================================================================
# Crash dumps DAO.

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
del _valid_access_flags
del n_MEM_ACCESS_ENUM
del n_MEM_ALLOC_ACCESS_ENUM

class MemoryDTO (BaseDTO):
    """
    Database mapping for memory dumps.
    """

    # Declare the table mapping.
    __tablename__ = 'memory'
    id            = Column(Integer, Sequence(__tablename__ + '_seq'),
                           primary_key = True)
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
    filename      = Column(TEXT)
    content       = deferred(Column(LargeBinary))

    def __init__(self, crash_id, mbi):
        """
        Process a L{win32.MemoryBasicInformation} object for database storage.
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
        Returns a L{win32.MemoryBasicInformation} object using the data
        retrieved from the database.

        @type  getMemoryDump: bool
        @param getMemoryDump: If C{True} retrieve the memory dump.
            Defaults to C{False} since this may be a costly operation.

        @rtype:  L{win32.MemoryBasicInformation}
        @return: Memory block information.
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

class CrashDTO (BaseDTO):
    """
    Database mapping for crash dumps.
    """

    # Table name.
    __tablename__ = "crashes"

    # Primary key.
    id = Column(Integer, Sequence(__tablename__ + '_seq'), primary_key = True)

    # Timestamp.
    timestamp = Column(DateTime, nullable = False, index = True)

    # Heuristic signature.
    signature = Column(LargeBinary, nullable = False)

    # Pickled Crash object, minus the memory dump.
    data = deferred(Column(LargeBinary, nullable = False))

    # Exploitability test.
    exploitable = Column(Integer, nullable = False)
    exploitability_rule = Column(TEXT, nullable = False)
    exploitability_rating = Column(TEXT, nullable = False)
    exploitability_desc = Column(TEXT, nullable = False)

    # Platform description.
    os = Column(TEXT, nullable = False)
    arch = Column(TEXT, nullable = False)
    bits = Column(Integer, nullable = False)

    # Event description.
    event = Column(Integer, nullable = False)
    pid = Column(Integer, nullable = False)
    tid = Column(Integer, nullable = False)
    pc = Column(BigInteger, nullable = False)
    sp = Column(BigInteger, nullable = False)
    fp = Column(BigInteger, nullable = False)
    pc_label = Column(TEXT, nullable = False)

    # Exception description.
    exception = Column(TEXT)
    exception_text = Column(TEXT)
    exception_address = Column(BigInteger)
    exception_label = Column(TEXT)
    first_chance = Column(Boolean)
    fault_type = Column(Integer)
    fault_address = Column(BigInteger)
    fault_label = Column(TEXT)
    fault_disasm = Column(TEXT)
    stack_trace = Column(TEXT)

    # Environment description.
    command_line = Column(TEXT)
    environment = Column(TEXT)

    # Notes.
    notes = Column(TEXT)

    def __init__(self, crash):
        """
        @type  crash: Crash
        @param crash: L{Crash} object to store into the database.
        """

        # Timestamp and signature.
        self.timestamp = datetime.datetime.fromtimestamp( crash.timeStamp )
        self.signature = buffer(pickle.dumps(crash.signature, protocol = 0))

        # Pickled Crash object, minus the memory dump.
        if crash.memoryMap:
            warnings.warn("Serializing a crash dump that contains a memory"
                          " dump may be very slow and take up more space in"
                          " the database!")
        self.data = buffer(Marshaller.dumps(crash))

        # Exploitability test.
        self.exploitability_rating, \
        self.exploitability_rule,   \
        self.exploitability_desc  = \
                                    crash.isExploitable()

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
        self.event    = crash.eventCode
        self.pid      = crash.pid
        self.tid      = crash.tid
        self.pc       = crash.pc
        self.sp       = crash.sp
        self.fp       = crash.fp
        self.pc_label = crash.labelPC

        # Exception description.
        self.exception         = crash.exceptionName
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

        # Environment description.
        self.command_line    = crash.commandLine
        if crash.environmentData is None:
            self.environment = None
        else:
            if type(crash.environmentData) == type(u''):
                self.environment = u'\0'.join(crash.environmentData) + u'\0'
            else:
                self.environment = '\0'.join(crash.environmentData) + '\0'

        # Notes.
        self.notes = crash.notesReport()

    def toCrash(self, getMemoryDump = False):
        """
        Returns a L{Crash} object using the data retrieved from the database.

        @type  getMemoryDump: bool
        @param getMemoryDump: If C{True} retrieve the memory dump.
            Defaults to C{False} since this may be a costly operation.

        @rtype:  L{Crash}
        @return: Crash object.
        """
        crash = Marshaller.loads(str(self.data))
        if not isinstance(crash, Crash):
            raise TypeError(
                "Expected Crash instance, got %s instead" % type(crash))
        crash._rowid = self.id
        if not crash.memoryMap:
            memory = getattr(self, "memory", [])
            if memory:
                crash.memoryMap = [dto.toMBI(getMemoryDump) for dto in memory]
        return crash

# Fix for MySQL databases only, where a special "length" parameter is required.
# See: http://docs.sqlalchemy.org/en/latest/dialects/mysql.html#mysql-indexes
idx_signature = Index('ix_crashes_signature', CrashDTO.signature,
                      mysql_length = 256)

#==============================================================================

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

class _EnableSQLiteForeignKeys (PoolListener):
    """
    Used internally by L{BaseDAO}.

    When connecting to an SQLite database, ensure that foreign keys support is
    enabled. If not, abort the connection.

    @see: U{http://sqlite.org/foreignkeys.html}
    """
    def connect(dbapi_con, connection_record):
        try:
            cursor = dbapi_con.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys = ON;")
                cursor.execute("PRAGMA foreign_keys;")
                if cursor.fetchone()[0] != 1:
                    raise Exception()
            finally:
                cursor.close()
        except Exception:
            dbapi_con.close()
            raise sqlite3.Error()

class BaseDAO (object):
    """
    Data Access Object base class.

    @type _url: sqlalchemy.url.URL
    @ivar _url: Database connection URL.

    @type _dialect: str
    @ivar _dialect: SQL dialect currently being used.

    @type _driver: str
    @ivar _driver: Name of the database driver currently being used.
        To get the actual Python module use L{_url}.get_driver() instead.

    @type _session: sqlalchemy.orm.Session
    @ivar _session: Database session object.

    @type _new_session: class
    @cvar _new_session: Custom configured Session class used to create the
        L{_session} instance variable.

    @type _echo: bool
    @cvar _echo: Set to C{True} to print all SQL queries to standard output.
    """

    _echo = False

    _new_session = sessionmaker(autoflush = True,
                                autocommit = True,
                                expire_on_commit = True,
                                weak_identity_map = True)

    def __init__(self, url = None, creator = None):
        """
        Connect to the database using the given connection URL.

        The current implementation uses SQLAlchemy and so it will support
        whatever database said module supports.

        @type  url: str
        @param url:
            URL that specifies the database to connect to.

            Examples:
             - Opening an SQLite file:
               C{dao = CrashDAO("sqlite:///C:\\some\\path\\database.sqlite")}
             - Connecting to a previously configured MS-SQL database using the
               C{PyODBC} library:
               C{dao = CrashDAO("mssql+pyodbc://MyDSN")}
             - Connecting to a MySQL database called "crashes" running locally
               using the C{oursql} library, authenticating as the "winappdbg"
               user with no password:
               C{dao = CrashDAO("mysql+oursql://winappdbg@localhost/crashes")}

            For more information see the C{SQLAlchemy} documentation online:
            U{http://docs.sqlalchemy.org/en/latest/core/engines.html}

        @type  creator: callable
        @param creator: (Optional) Callback function that creates the SQL
            database connection.

            Normally it's not necessary to use this argument. However in some
            odd cases you may need to customize the database connection, for
            example when using the integrated authentication in MSSQL.
        """

        # Parse the connection URL.
        parsed_url = URL(url)
        schema = parsed_url.drivername
        if '+' in schema:
            dialect, driver = schema.split('+')
        else:
            dialect, driver = schema, 'base'
        dialect = dialect.strip().lower()
        driver = driver.strip()

        # Load the database engine.
        if dialect == 'sqlite':
            engine = create_engine(url,
                                   echo = self._echo,
                                   module = sqlite3.dbapi2,
                                   listeners = [_EnableSQLiteForeignKeys()],
                                   creator = creator)
        else:
            engine = create_engine(url,
                                   echo = self._echo,
                                   creator = creator)

        # Create a new session.
        session = self._new_session(bind = engine)

        # Create the required tables if they don't exist.
        BaseDTO.metadata.create_all(engine)

        # Set the instance properties.
        self._url     = parsed_url
        self._driver  = driver
        self._dialect = dialect
        self._session = session

    def _transactional(self, method, *argv, **argd):
        """
        Begins a transaction and calls the given DAO method.

        If the method executes successfully the transaction is commited.

        If the method fails, the transaction is rolled back.

        @type  method: callable
        @param method: Bound method of this class or one of its subclasses.
            The first argument will always be C{self}.

        @return: The return value of the method call.

        @raise Exception: Any exception raised by the method.
        """
        self._session.begin(subtransactions = True)
        try:
            result = method(self, *argv, **argd)
            self._session.commit()
            return result
        except:
            self._session.rollback()
            raise

@decorator
def Transactional(fn, self, *argv, **argd):
    """
    Decorator that wraps DAO methods to handle transactions automatically.

    It may only work with subclasses of L{BaseDAO}.
    """
    return self._transactional(fn, *argv, **argd)

#==============================================================================

# TODO: add a method to modify already stored crash dumps.

class CrashDAO (BaseDAO):
    """
    Data Access Object to read, write and search for L{Crash} objects in a
    database.
    """

    @Transactional
    def add(self, crash, allow_duplicates = True):
        """
        Add a new crash dump to the database.

        @type  crash: L{Crash}
        @param crash: Crash object.

        @type  allow_duplicates: bool
        @param allow_duplicates: C{True} to always add the new crash dump.
            C{False} to only add the crash dump if no other crash with the
            same signature is found in the database.

            Sometimes, your fuzzer turns out to be I{too} good. Then you find
            youself browsing through gigabytes of crash dumps, only to find
            a handful of actual bugs in them. This simple heuristic filter
            saves you the trouble by discarding crashes that seem to be similar
            to another one you've already found.
        """

        # Filter out duplicated crashes, if requested.
        if not allow_duplicates:
            signature = buffer(pickle.dumps(crash.signature, protocol = 0))
            if self._session.query(CrashDTO.id)                \
                            .filter_by(signature = signature) \
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

            # Take out the memory map from the Crash object,
            # so it doesn't get pickled into the database.
            memoryMap = crash.memoryMap
            crash.memoryMap = None

            # Fill out a new row for the crashes table.
            r_crash = CrashDTO(crash)
            session.add(r_crash)

            # Flush and get the new row ID.
            session.flush()
            crash_id = r_crash.id

        finally:
            try:

                # Make the ORM forget the CrashDTO object so we can
                # safely restore the memory map into the Crash object.
                if r_crash is not None:
                    session.expire(r_crash)

            finally:

                # Just in case, delete the last reference to the CrashDTO
                # object, so the Python garbage collector claims it.
                del r_crash

                # Restore the memory map of the Crash object.
                crash.memoryMap = memoryMap

        # Return the row ID for the Crash object.
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
        Retrieve all L{Crash} objects in the database, optionally filtering
        them by signature and timestamp, and/or sorting them by timestamp.

        Results can be paged to avoid consuming too much memory if the database
        is large.

        @see: L{find_by_example}

        @type  signature: object
        @param signature: (Optional) Return only through crashes matching
            this signature. See L{Crash.signature} for more details.

        @type  order: int
        @param order: Sort by timestamp.
            If C{== 0}, results are not sorted.
            If C{> 0}, results are sorted from older to newer.
            If C{< 0}, results are sorted from newer to older.

        @type  since: datetime
        @param since: (Optional) Return only the crashes after and
            including this date and time.

        @type  until: datetime
        @param until: (Optional) Return only the crashes before this date
            and time, not including it.

        @type  offset: int
        @param offset: (Optional) Skip the first I{offset} results.

        @type  limit: int
        @param limit: (Optional) Return at most I{limit} results.

        @rtype:  list(L{Crash})
        @return: List of Crash objects.
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
            sig_buffer = buffer(pickle.dumps(signature, protocol = 0))
            query = query.filter(CrashDTO.signature == sig_buffer)
        if since:
            query = query.filter(CrashDTO.timestamp >= since)
        if until:
            query = query.filter(CrashDTO.timestamp < until)
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)
        if order:
            if order > 0:
                query = query.asc(CrashDTO.timestamp)
            else:
                query = query.desc(CrashDTO.timestamp)

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

        @see: L{find}

        @type  crash: L{Crash}
        @param crash: Crash object to compare with. Fields set to C{None} are
            ignored, all other fields but the signature are used in the
            comparison.

            To search for signature instead use the L{find} method.

        @type  offset: int
        @param offset: (Optional) Skip the first I{offset} results.

        @type  limit: int
        @param limit: (Optional) Return at most I{limit} results.

        @rtype:  list(L{Crash})
        @return: List of similar crash dumps found.
        """

        # Validate the parameters.
        if limit is not None and not limit:
            warnings.warn("CrashDAO.find_by_example() was set a limit of 0"
                          " results, returning without executing a query.")
            return []

        # Build the query.
        query = self._session.query(CrashDTO)

        # Build a CrashDTO from the Crash object.
        dto = CrashDTO(crash)

        # Filter all the fields in the crashes table that are present in the
        # CrashDTO object and not set to None, except for the row ID.
        for name, column in CrashDTO.__dict__.iteritems():
            if not name.startswith('__') and name not in ('id',
                                                          'signature',
                                                          'data'):
                if isinstance(column, Column):
                    value = getattr(dto, name, None)
                    if value is not None:
                        query = query.filter(column == value)

        # Page the query.
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
    def count(self, signature = None):
        """
        Counts how many crash dump have been stored in this database.
        Optionally filters the count by heuristic signature.

        @type  signature: object
        @param signature: (Optional) Count only the crashes that match
            this signature. See L{Crash.signature} for more details.

        @rtype:  int
        @return: Count of crash dumps stored in this database.
        """
        query = self._session.query(CrashDTO.id)
        if signature:
            sig_buffer = buffer(pickle.dumps(signature, protocol = 0))
            query = query.filter_by(signature = sig_buffer)
        return query.count()

    @Transactional
    def delete(self, crash):
        """
        Remove the given crash dump from the database.

        @type  crash: L{Crash}
        @param crash: Crash dump to remove.
        """
        query = self._session.query(CrashDTO).filter_by(id = crash._rowid)
        query.delete(synchronize_session = False)
        del crash._rowid
