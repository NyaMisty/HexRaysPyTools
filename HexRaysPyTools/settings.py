import os
import logging
import ida_diskio

try:
    import configparser
except ImportError:
    # for python 2
    import ConfigParser as configparser

CONFIG_FILE_PATH = os.path.join(ida_diskio.get_user_idadir(), 'cfg', 'HexRaysPyTools.cfg')
CONFIG_DIRECTORY = os.path.join(ida_diskio.get_user_idadir(), 'cfg')

DEBUG_MESSAGE_LEVEL = logging.INFO
# Whether propagate names (Propagate name feature) through all names or only defaults like v11, a3, this, field_4
PROPAGATE_THROUGH_ALL_NAMES = False
# Store Xref information in database. I don't know how much size it consumes yet
STORE_XREFS = True
# There're some types that can be pointers to structures like int, PVOID etc and by default plugin scans only them
# Full list can be found in `Const.LEGAL_TYPES`.
# But if set this option to True than variable of every type could be possible to scan
SCAN_ANY_TYPE = False

TEMPLATED_TYPES_FILE = os.path.join(
                os.path.dirname(__file__), 'types', 'templated_types.toml')


def add_default_settings(config):
    updated = False
    if not config.has_option("DEFAULT", "DEBUG_MESSAGE_LEVEL"):
        config.set(None, 'DEBUG_MESSAGE_LEVEL', str(DEBUG_MESSAGE_LEVEL))
        updated = True
    if not config.has_option("DEFAULT", "PROPAGATE_THROUGH_ALL_NAMES"):
        config.set(None, 'PROPAGATE_THROUGH_ALL_NAMES', str(PROPAGATE_THROUGH_ALL_NAMES))
        updated = True
    if not config.has_option("DEFAULT", "STORE_XREFS"):
        config.set(None, 'STORE_XREFS', str(STORE_XREFS))
        updated = True
    if not config.has_option("DEFAULT", "SCAN_ANY_TYPE"):
        config.set(None, 'SCAN_ANY_TYPE', str(SCAN_ANY_TYPE))
        updated = True
    if not config.has_option("DEFAULT", "TEMPLATED_TYPES_FILE"):
        config.set(None, 'TEMPLATED_TYPES_FILE', str(TEMPLATED_TYPES_FILE))
        updated = True

    if updated:
        try:
            if not os.path.exists(CONFIG_DIRECTORY):
                os.makedirs(CONFIG_DIRECTORY)
            with open(CONFIG_FILE_PATH, "w") as f:
                config.write(f)
        except IOError:
            print("[ERROR] Failed to write or update config file at {}. Default settings will be used instead.\n" \
                  "Consider running IDA Pro under administrator once".format(CONFIG_FILE_PATH))


def load_settings():
    global                           \
        DEBUG_MESSAGE_LEVEL,         \
        PROPAGATE_THROUGH_ALL_NAMES, \
        STORE_XREFS,                 \
        SCAN_ANY_TYPE,               \
        TEMPLATED_TYPES_FILE

    config = configparser.ConfigParser()
    if os.path.isfile(CONFIG_FILE_PATH):
        config.read(CONFIG_FILE_PATH)

    add_default_settings(config)

    DEBUG_MESSAGE_LEVEL = config.getint("DEFAULT", 'DEBUG_MESSAGE_LEVEL')
    PROPAGATE_THROUGH_ALL_NAMES = config.getboolean("DEFAULT", 'PROPAGATE_THROUGH_ALL_NAMES')
    STORE_XREFS = config.getboolean("DEFAULT", 'STORE_XREFS')
    SCAN_ANY_TYPE = config.getboolean("DEFAULT", 'SCAN_ANY_TYPE')
    TEMPLATED_TYPES_FILE = config.get("DEFAULT", 'TEMPLATED_TYPES_FILE')
