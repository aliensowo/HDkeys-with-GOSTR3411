from ldap3 import Server, Connection, ALL, Reader,ObjectDef
from ldap3.core.exceptions import LDAPKeyError, LDAPBindError, LDAPCursorAttributeError
from ldap3.abstract.attribute import Attribute
from ldap3.abstract.entry import Entry
from typing import List

AUTH_LDAP_SERVER_URI = ""
LDAP_DN = ""
LDAP_PASSWD = ""
LDAP_BASE_FIELD = ""
LDAP_FILTER = ""
LDAP_SEARCH_ROOT = ""
PARAM_KEYS = ""
GENERAL_ObjectClass_VALUE = ""


# sync ldap directory
def ldap_sync():
    server = Server(AUTH_LDAP_SERVER_URI, get_info=ALL)
    try:
        conn = Connection(server, LDAP_DN, LDAP_PASSWD, auto_bind=True, check_names=True)
    except LDAPBindError:
        raise ConnectionError
    inetorgperson = ObjectDef(GENERAL_ObjectClass_VALUE.split(","), conn)
    reader = Reader(conn, inetorgperson, LDAP_SEARCH_ROOT)
    search_result: List[Entry] = reader.search()
    result = {}
    for entity in search_result:
        result[str(entity.cn)] = {}
        for param in PARAM_KEYS.split(","):
            try:
                result[str(entity.cn)][param] = entity.__getattr__(param).value
                # print(entity.__getattr__(param))
            except LDAPCursorAttributeError:
                result[str(entity.cn)][param] = None
        # TODO: record user in DB
    return result


def ldap_entry(username: str, password: str) -> dict:
    """
    {
        'status': 'good',
        'status_msg': '*** Successful bind to ldap server',
        'params': {
            'username': userdata_login,
            'mail': userdata_mail,
            'displayName': userdata_name,
            'gecos': userdata_fio,
            'apple-birthday': userdata_dateFormat
        }
    }
    :param username: ldap username
    :param password: ldap password
    :return: dict
    """
    ldap_user_name = username.strip()
    ldap_user_pwd = password.strip()
    ldsp_server = AUTH_LDAP_SERVER_URI
    user = f'uid={ldap_user_name},{LDAP_SEARCH_ROOT}'
    server = Server(ldsp_server, get_info=ALL)
    connection = Connection(server, user=user, password=ldap_user_pwd)
    result = {}
    if not connection.bind():
        result.update({
            "status": f"bad",
            "status_msg": f"** Failed Authentication: {connection.last_error}",
        })
    else:
        connection.search(LDAP_DN,
                          f"(&(uid={ldap_user_name})(objectClass=inetOrgPerson))",
                          attributes=['*'])
        entry = connection.entries[0]
        result = {"status": "good", "status_msg": "*** Successful bind to ldap server", 'params': {}}
        for param in PARAM_KEYS.split(","):
            # print(entry[param], type(entry[param]))
            a:Attribute = entry[param]
            try:
                result['params'][a.key] = a.value
            except LDAPKeyError:
                result['params'][param] = None
    return result


def eq_split(s: str, sep="=") -> str:
    return s.split(sep)[-1].strip()


print(ldap_sync())